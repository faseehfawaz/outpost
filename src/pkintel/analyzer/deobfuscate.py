"""Static PHP-kit deobfuscator — a PURE STRING TRANSFORM. It NEVER runs PHP.

Phishing kits routinely wrap their real source in nested decoder chains, e.g.::

    eval(gzinflate(base64_decode('7b0Ha...')));
    eval(str_rot13(base64_decode('PD9w...')));

We do NOT execute these. We recognise the *wrapper syntax*, pull out the quoted
**string literal**, and apply the equivalent decoding to that literal's bytes
ourselves (base64, raw/zlib/gzip inflate, rot13, reverse, url-decode). ``eval``,
``assert``, ``create_function`` and friends are treated purely as markers that
"the argument is the next layer" — they are stripped, never invoked.

Anything we cannot statically decode is left as-is (detect-only). The result is
the most-decoded form reached after at most ``max_rounds`` passes.

Non-negotiable: there is no ``eval``/``exec``/``compile`` of attacker content in
this module. Every transform is a deterministic byte operation from the standard
library.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import zlib
from urllib.parse import unquote_to_bytes

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
_DECODERS: dict[str, "callable"] = {}


def _dec(name: str):
    def _register(fn):
        _DECODERS[name] = fn
        return fn

    return _register


@_dec("base64_decode")
def _base64_decode(data: bytes) -> bytes:
    # tolerate whitespace and missing padding
    cleaned = re.sub(rb"\s+", b"", data)
    pad = (-len(cleaned)) % 4
    return base64.b64decode(cleaned + (b"=" * pad), validate=False)


@_dec("gzinflate")
def _gzinflate(data: bytes) -> bytes:
    return zlib.decompress(data, -zlib.MAX_WBITS)  # raw DEFLATE (no header)


@_dec("gzuncompress")
def _gzuncompress(data: bytes) -> bytes:
    return zlib.decompress(data)  # zlib header


@_dec("gzdecode")
def _gzdecode(data: bytes) -> bytes:
    return zlib.decompress(data, zlib.MAX_WBITS | 16)  # gzip header


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
_CHAIN_RE = re.compile(
    r"""
    (?P<funcs>(?:@?\s*[A-Za-z_]\w*\s*\(\s*)+)   # one or more `func(`
    (?P<q>['"])                                 # opening quote
    (?P<body>(?:\\.|(?!(?P=q)).)*)              # literal body (escapes allowed)
    (?P=q)                                      # closing quote
    \s*\)+                                       # closing parens
    """,
    re.VERBOSE | re.DOTALL,
)

_FUNC_NAME_RE = re.compile(r"@?\s*([A-Za-z_]\w*)\s*\(")


def _unescape_php_literal(body: str) -> bytes:
    r"""Turn a PHP single/double-quoted literal body into raw bytes.

    Handles the common escapes (\n \r \t \\ \" \' \0 and \xNN). Good enough for
    the base64/compressed payloads kits use; anything exotic falls back to the
    literal bytes, which is safe (we simply fail to decode and leave it).
    """
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
    """Apply a decoder chain to ``literal``; return decoded text or ``None``.

    ``funcs_blob`` is the outer-to-inner sequence of ``func(`` tokens. We drop
    executor names (eval/assert/...), reverse to inner-to-outer, and apply each
    known decoder in turn. If any layer is unknown or fails, we give up on this
    chain (``None``) — detect-only, never guess-execute.
    """
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


def _one_round(text: str) -> str:
    """Decode every decodable wrapper chain found in ``text`` once."""

    def _sub(m: "re.Match[str]") -> str:
        decoded = _apply_chain(m.group("funcs"), m.group("body"))
        return decoded if decoded is not None else m.group(0)

    return _CHAIN_RE.sub(_sub, text)


def deobfuscate(text: str, max_rounds: int = 25) -> str:
    """Iteratively decode common PHP obfuscation layers; return the decoded form.

    Pattern-matches decoder wrappers and decodes the STRING LITERAL only. Stops
    when a pass makes no progress or ``max_rounds`` is reached. Never executes
    anything; undecodable content is returned unchanged.
    """
    current = text
    for _ in range(max(1, max_rounds)):
        nxt = _one_round(current)
        if nxt == current:
            break
        current = nxt
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
