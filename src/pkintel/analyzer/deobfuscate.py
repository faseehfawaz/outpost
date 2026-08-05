"""Multi-layer PHP deobfuscation engine.

Phishing kits overwhelmingly rely on a small set of obfuscation
patterns — nested ``eval(gzinflate(base64_decode('...')))`` chains, hex
or octal escape sequences, and simple variable-substitution wrappers.
This module peels those layers iteratively so the indicator extractor
can work on readable source.

**Design constraints**

* Must run inside the analyzer sandbox (no network, limited CPU/RAM).
* Must be *safe* against intentionally malformed payloads — e.g. a
  base64 blob that decodes to 4 GB of nulls.  Every decode helper
  therefore has an output-size cap and a round limit.
* Must never ``exec``/``eval`` anything.  We only *pattern-match* PHP
  ``eval()`` calls and strip them; we never execute the content.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import logging
import re
import time
import zlib
from urllib.parse import unquote_to_bytes

log = logging.getLogger(__name__)

# Safety caps — prevent zip-bomb and oversized-file abuse (P0-5, audit).
_MAX_DECODED = 32 * 1024 * 1024  # 32 MB max decompressed output
_MAX_BASE64_INPUT = 48 * 1024 * 1024  # 48 MB max base64 input (~36 MB decoded)
# 2 MB, lowered from 5 MB. A legitimate PHP source file is a few hundred KB at
# the very outside; anything larger is either a bundled asset (nothing to
# deobfuscate) or a deliberate attempt to maximise parser work.
_MAX_FILE_SIZE = 2 * 1024 * 1024
_DEOBFUSCATE_TIMEOUT_S = 20.0  # per-file wall-clock budget

# Functions that merely *execute* / emit their argument. We drop them and keep
# decoding the inner argument; we never run them.
_EXECUTORS = {
    "eval",
    "assert",
    "print",
    "printf",
    "echo",
    "create_function",
    "call_user_func",
    "system",
    "passthru",
    "shell_exec",
}

# Decoders we can reproduce as pure byte transforms.
_DECODERS: dict[str, callable] = {}


def _dec(name: str):
    def _register(fn):
        _DECODERS[name] = fn
        return fn

    return _register


@_dec("base64_decode")
def _base64_decode(data: bytes) -> bytes:
    if len(data) > _MAX_BASE64_INPUT:
        raise ValueError("base64 input exceeds size cap")
    # tolerate whitespace and missing padding
    cleaned = re.sub(rb"\s+", b"", data)
    pad = (-len(cleaned)) % 4
    return base64.b64decode(cleaned + (b"=" * pad), validate=False)


@_dec("gzinflate")
def _gzinflate(data: bytes) -> bytes:
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    out = d.decompress(data, _MAX_DECODED)
    if d.unconsumed_tail:
        raise ValueError("decompression cap exceeded")
    return out


@_dec("gzuncompress")
def _gzuncompress(data: bytes) -> bytes:
    d = zlib.decompressobj()
    out = d.decompress(data, _MAX_DECODED)
    if d.unconsumed_tail:
        raise ValueError("decompression cap exceeded")
    return out


@_dec("gzdecode")
def _gzdecode(data: bytes) -> bytes:
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    out = d.decompress(data, _MAX_DECODED)
    if d.unconsumed_tail:
        raise ValueError("decompression cap exceeded")
    return out


@_dec("str_rot13")
def _str_rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("latin-1"), "rot_13").encode("latin-1")


@_dec("strrev")
def _strrev(data: bytes) -> bytes:
    return data[::-1]


@_dec("rawurldecode")
def _rawurldecode(data: bytes) -> bytes:
    return unquote_to_bytes(data)


@_dec("urldecode")
def _urldecode(data: bytes) -> bytes:
    return unquote_to_bytes(data.replace(b"+", b" "))


@_dec("convert_uudecode")
def _convert_uudecode(data: bytes) -> bytes:
    return binascii.a2b_uu(data)


# A chain is a stack of `func(` prefixes wrapping a single quoted string literal,
# e.g.  eval ( gzinflate ( base64_decode ( '....' ) ) )
#
# ReDoS history — this pattern has bitten twice, so the shape is deliberate:
#
# 1. EXPONENTIAL (original). The body was `(?:\\.|(?!(?P=q)).)*`. Both branches
#    could match a backslash, so an unterminated literal followed by N
#    backslashes made the engine explore 2^N ways to split them. Measured 3.7 s
#    at N=32, growing x2.6 per two backslashes — roughly six hours at N=50 from
#    a ~60-byte file. Fixed by making the branches disjoint: `\\.` takes escape
#    pairs, `[^'"\\]` takes everything else, and no input matches both.
#
# 2. QUADRATIC (introduced by that fix). The culprit is the UNBOUNDED `\w*` in
#    the function-name part. `search()` retries at every offset; inside a long
#    body each retry let `\w*` run to end-of-string and then backtrack one
#    character at a time looking for `(`. That is O(n) work at O(n) offsets —
#    measured x4.00 per doubling, 10.7 s at 40 KB, extrapolating to ~44 h at a
#    5 MB file. Bounding it to `\w{0,63}` caps each retry at a constant, which
#    makes the whole scan linear. PHP function names are short; 64 characters
#    is far beyond anything real, and the only cost of being wrong is missing
#    one exotic chain.
#
#    Note `[ \t]` rather than `\s`, and no DOTALL: a decoder chain is written
#    on one line, so a match attempt should never be able to run past a
#    newline. That bounds the body scan to a single line as well.
#
# Anything that still gets through is caught by the wall-clock budget in
# deobfuscate(), which — unlike the version this replaces — actually fires.
_CHAIN_RE = re.compile(
    r"""
    (?P<funcs>(?:@?[ \t]*[A-Za-z_]\w{0,63}[ \t]*\([ \t]*){1,8})  # up to 8 nested calls
    (?P<q>['"])                                                   # opening quote
    (?P<body>(?:\\[^\n]|[^'"\\\n]){0,1000000})                   # disjoint, single-line
    (?P=q)                                                        # closing quote
    [ \t]*\)+                                                     # closing parens
    """,
    re.VERBOSE,
)

_FUNC_NAME_RE = re.compile(r"@?[ \t]*([A-Za-z_]\w{0,63})[ \t]*\(")

# Optional: the third-party `regex` module supports a real per-call timeout,
# which stdlib `re` does not. When present we use it as an extra backstop so a
# single pathological match attempt cannot run away even if a future edit
# reintroduces a super-linear pattern. Absence changes nothing functionally —
# the pattern above is linear-time on its own.
_REGEX_CHAIN_RE = None
try:  # pragma: no cover - depends on optional dependency
    import regex as _regex_mod

    _REGEX_CHAIN_RE = _regex_mod.compile(_CHAIN_RE.pattern, _regex_mod.VERBOSE)
except ImportError:  # pragma: no cover
    pass


def _unescape_php_literal(body: str) -> bytes:
    r"""Turn a PHP single/double-quoted literal body into raw bytes."""
    out = bytearray()
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            nxt = body[i + 1]
            simple = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39, "0": 0}
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < n:
                try:
                    out.append(int(body[i + 2 : i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            out.append(ord("\\"))
            i += 1
            continue
        out.append(ord(ch) & 0xFF)
        i += 1
    return bytes(out)


def _apply_chain(funcs_blob: str, literal: str) -> str | None:
    """Apply a decoder chain to ``literal``; return decoded text or ``None``."""
    names = _FUNC_NAME_RE.findall(funcs_blob)  # outer -> inner
    decoders = [name for name in names if name not in _EXECUTORS]
    if not decoders:
        return None
    # innermost decoder is applied to the literal first
    order = list(reversed(decoders))
    data = _unescape_php_literal(literal)
    for name in order:
        fn = _DECODERS.get(name)
        if fn is None:
            return None  # can't statically decode this layer
        try:
            data = fn(data)
        except Exception:
            return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


class _DeobfuscationTimeout(Exception):
    """Raised internally when a file exceeds its wall-clock budget."""


def _one_round(text: str, deadline: float) -> str:
    """Decode every decodable wrapper chain found in ``text`` once.

    The deadline is checked once per match rather than once per round: a file
    with thousands of small chains costs its time in aggregate, not in any one
    match, so a per-round check would overshoot badly.
    """

    def _sub(m: re.Match[str]) -> str:
        if time.monotonic() > deadline:
            raise _DeobfuscationTimeout
        decoded = _apply_chain(m.group("funcs"), m.group("body"))
        return decoded if decoded is not None else m.group(0)

    if _REGEX_CHAIN_RE is not None:
        # `regex` supports a real per-call timeout, so a single pathological
        # match attempt cannot run away. `re` has no such parameter.
        remaining = max(0.001, deadline - time.monotonic())
        return _REGEX_CHAIN_RE.sub(_sub, text, timeout=remaining)
    return _CHAIN_RE.sub(_sub, text)


def deobfuscate(
    source: str,
    max_rounds: int = 25,
    *,
    timeout_s: float = _DEOBFUSCATE_TIMEOUT_S,
) -> str:
    """Iteratively decode common PHP obfuscation layers; return the decoded form.

    Pattern-matches decoder wrappers and decodes the STRING LITERAL only. Stops
    when a pass makes no progress, ``max_rounds`` is reached, or ``timeout_s``
    elapses. Never executes anything; undecodable content is returned unchanged.

    Timeout semantics — read this before changing it
    ------------------------------------------------
    An earlier revision wrapped this in ``ThreadPoolExecutor`` +
    ``future.result(timeout=...)``. That does not work, for two independent
    reasons, and it is worth stating both because the code looked correct:

    1. CPython's ``re`` does not release the GIL while matching. A runaway
       match in a worker thread holds the GIL, so the calling thread is never
       scheduled to raise ``TimeoutError``.
    2. ``with ThreadPoolExecutor(...)`` calls ``shutdown(wait=True)`` on exit,
       so even a timeout that *did* fire would then block on ``__exit__`` until
       the runaway thread finished.

    Measured: a 1.2 MB payload with ``timeout_s=3`` ran past 44 s.

    What we do instead, in layers:

    * the pattern itself is linear-time (see ``_CHAIN_RE``) — this is the real
      defence, not the timeout;
    * a cooperative deadline checked per match bounds aggregate work;
    * if the optional ``regex`` module is installed we get a true per-match
      timeout as well;
    * and in production the analyzer runs inside a container with
      ``--timeout``/``--memory``, which is the only genuinely hard boundary
      (see ``pkintel.analyzer.runner``).
    """
    if len(source) > _MAX_FILE_SIZE:
        log.warning(
            "Skipping deobfuscation: file size %d exceeds %d byte cap", len(source), _MAX_FILE_SIZE
        )
        return source

    deadline = time.monotonic() + timeout_s
    current = source
    try:
        for _ in range(max(1, max_rounds)):
            nxt = _one_round(current, deadline)
            if nxt == current:
                break
            current = nxt
            if time.monotonic() > deadline:
                raise _DeobfuscationTimeout
    except _DeobfuscationTimeout:
        log.error("Deobfuscation exceeded its %.1fs budget; returning best effort", timeout_s)
    except Exception as exc:  # noqa: BLE001 - includes regex.TimeoutError
        log.error("Deobfuscation aborted: %s", exc)
    return current


# --- obfuscation heuristic -------------------------------------------------
_EVAL_DECODE_RE = re.compile(
    r"(?:eval|assert|create_function)\s*\(\s*@?\s*"
    r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev)",
    re.IGNORECASE,
)
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){20,}")
_CHR_CHAIN_RE = re.compile(r"(?:chr\(\d+\)\s*\.?\s*){10,}", re.IGNORECASE)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from math import log2

    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def is_obfuscated(text: str) -> bool:
    """Heuristic: does this source look deliberately obfuscated?

    True when we see an ``eval``/``assert`` fed by a decoder, a very long single
    line, a long base64 blob, dense ``\\xNN`` / ``chr()`` chains, or a
    high-entropy long line. Cheap and conservative — used only to flag files.
    """
    if not text:
        return False
    if _EVAL_DECODE_RE.search(text):
        return True
    if _LONG_B64_RE.search(text):
        return True
    if _HEX_ESCAPE_RE.search(text) or _CHR_CHAIN_RE.search(text):
        return True
    lines = text.splitlines() or [text]
    longest = max(lines, key=len)
    if len(longest) > 2000:
        return True
    if len(longest) > 400 and _shannon_entropy(longest) > 5.2:
        return True
    return False
