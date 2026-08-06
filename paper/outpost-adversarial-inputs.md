# The Analyser Is the Target: Adversarial Inputs Against Phishing-Kit Analysis Pipelines

**Faseeh Padinjarathil**
Independent Researcher · Dubai, United Arab Emirates
`security@heapleap.tech` · ORCID: [0009-0000-4874-6459](https://orcid.org/0009-0000-4874-6459)

**Version 1.0 — August 2026**
*Technical report. Not peer reviewed.*

---

## Abstract

Phishing-kit intelligence pipelines collect and statically analyse archives written by the adversaries they are built to track. This inverts the usual assumption behind input validation: such a tool does not merely *encounter* hostile input occasionally, it consumes hostile input **by construction**, from an adversary who chooses that input freely and benefits directly from the tool failing. We argue the analyser is therefore part of the attack surface, and that an operator can disable the tooling hunting them by leaving a crafted file where the collector will find it — a pull-based attack in which the target fetches the payload voluntarily.

We substantiate this with a case study of four defects in a production pipeline, each remotely triggerable by planting a file in an open directory, each able to halt kit analysis indefinitely. A 38-byte PHP file induced exponential backtracking in the deobfuscator's pattern matcher, measured at ×2.60 growth per two additional backslashes and extrapolating to roughly 5.5 hours at *n*=50. Repairing that defect introduced a **second**, quadratic one at ×3.96 per doubling — worse in practice, because it requires no unusual bytes. A timeout added to bound the damage could not fire at all, for two independent reasons rooted in CPython's GIL and `ThreadPoolExecutor` semantics. Separately, an unbounded `zlib` call inflated a 1 MB blob to 1 GB in process memory.

After mitigation, growth is linear at ×2.02 per doubling, the worst case at the file-size cap falls to 2.28 s, decompression bombs are rejected in under 0.1 s, the wall-clock budget is enforced to within 0.01 s of its setting, and a hostile archive combining all four payloads with live indicators completes in 0.76 s with every indicator still extracted.

We report one further finding we consider as important as any individual bug: the pipeline's documentation, configuration, container definition and deployment manifests all described a hardened analysis sandbox — `--network none`, non-root, read-only filesystem, bounded timeout — that no code path had ever invoked. Four configuration settings governing it were dead, the container image referenced an entrypoint module that did not exist, and the host was granted root-equivalent Docker access to support it. The guarantee existed only in prose.

All measurements are reproducible with a single self-contained script included with this report.

**Keywords:** phishing kits, threat intelligence, ReDoS, algorithmic complexity attacks, decompression bombs, sandboxing, adversarial input, security of security tools

---

## 1. Introduction

A phishing-kit intelligence pipeline runs roughly the following loop. It ingests candidate URLs from public feeds and Certificate Transparency logs; triages them to decide which are live credential-harvesting pages; for confirmed phishing sites, checks opportunistically whether the operator left their source archive exposed in an open directory; downloads such archives; and statically analyses the contents to recover exfiltration channels — Telegram bot tokens, Discord and Slack webhooks, dropbox email addresses. Those indicators are clustered to link kits to a common operator, and abuse notices are filed.

Every stage after collection parses data the adversary wrote.

This is not the usual threat model for input validation. A web application parses input from users who are mostly benign, and hardening addresses the minority who are not. A phishing-kit analyser parses input that is *entirely* adversarial, from an adversary who controls the file's contents completely. The adversary also knows — or can trivially discover, since collectors are open source — that such pipelines exist and which filenames they probe for.

The delivery mechanism is therefore trivial. An operator who suspects they are being collected from does not need to locate the analyser or reach it over the network. They place a file named `kit.zip` in their own open directory and wait. **The target comes to the payload.**

We found no hardening against this in the pipeline we examined — a system written with unusual care in every other respect, including a published ethics policy with rate limits enforced in code rather than documentation.

### 1.1 Contributions

1. A threat model in which the security-analysis tool is the target and delivery is pull-based (§3).
2. Four remotely-triggerable availability defects in a production pipeline, with measurements (§4–5).
3. An account of how repairing one defect introduced a second, and how the mitigation intended to bound both was inert — a pattern we expect to recur (§4.2–4.3).
4. Mitigations and their measured effect (§6).
5. Evidence that a documented sandbox guarantee had never been implemented, and an argument that security properties stated in documentation should be asserted by tests (§7.1).
6. A self-contained reproduction script regenerating every table (§9).

### 1.2 What this report is not

A single-system case study. We have not yet surveyed other tools, so we cannot claim the defect class is widespread — only that it is cheap to exploit, that the pipeline we examined exhibited it in four distinct forms, and that the conditions producing it are not unusual. §12 describes the survey that would settle the question.

---

## 2. Background

### 2.1 Opportunistic kit collection

Phishing operators frequently deploy a kit by uploading an archive to a compromised host and unpacking it in place, leaving the archive behind. Where directory listing is enabled, or where the archive uses one of a small set of predictable names, it can be retrieved with an ordinary unauthenticated GET. This is the primary route by which researchers obtain kit source.

Collection is *opportunistic*: the pipeline does not attack the host, it requests a file the operator left publicly readable. That property is what makes the practice defensible — and it is also precisely what makes the attack in this report possible, because anything in that directory will be fetched.

### 2.2 Static analysis of kit source

Kits are predominantly PHP. Operators routinely wrap credential-handling logic in nested decoder chains:

```php
eval(gzinflate(base64_decode('7b0Ha...')));
eval(str_rot13(base64_decode('PD9w...')));
```

A static analyser must recover the inner source without executing it. The standard approach — used by the system studied here — pattern-matches the *wrapper syntax*, extracts the quoted string literal, and applies the equivalent decoding to those bytes directly. `eval`, `assert` and `create_function` are treated purely as markers that the argument is the next layer; they are stripped, never invoked. The process iterates until a pass makes no progress.

This is safe with respect to code execution. It is not automatically safe with respect to availability, and that gap is the subject of this report.

### 2.3 The system studied

Outpost is a phishing-kit intelligence pipeline of **12,758 lines of Python across 90 modules**, with a test suite of 237 functions in 3,327 lines. It has run continuously on a single node (6C/12T, 32 GB, SATA SSD) since July 2026, drawing from 16 feed adapters plus a Certificate Transparency firehose. At the time of writing it had ingested over 50,000 candidate URLs.

Nine batch stages, a long-lived CT consumer and a reaper are coordinated through PostgreSQL using `SELECT ... FOR UPDATE SKIP LOCKED`, with no message broker. State lives in six SQL migrations.

The **reaper** matters for what follows. It returns rows whose worker lease has expired, and it is a correct and necessary mechanism — without it, a worker killed mid-batch pins its rows in a busy state permanently. Combined with an input that reliably hangs a worker, however, it becomes an amplifier.

---

## 3. Threat model

**Adversary.** A phishing operator who suspects, or simply assumes, that automated collectors retrieve exposed archives from their infrastructure. They need no knowledge of which pipeline is collecting, no network access to it, and no ability to observe its behaviour.

**Capability.** Full control of the byte content of any file in their own web directory, and the ability to place arbitrarily many such files at negligible cost.

**Delivery.** Pull-based. The adversary transmits nothing; the target retrieves the payload voluntarily, through a code path specifically designed to find files like it. Ingress filtering and network segmentation are irrelevant, because the connection is outbound and initiated by the victim.

**Goal.** Availability. Halt or degrade analysis so that kits are not dissected, exfiltration channels are not published, and infrastructure is neither clustered nor reported. This is a substantially lower bar than code execution, and correspondingly easier to reach.

**Out of scope.** Code execution in the analyser; data poisoning aimed at corrupting the actor graph; attacks on the collector's network position. All are plausible and worth study. This report concerns availability.

### 3.1 Why lease-based recovery amplifies the attack

In a pipeline with lease-based recovery, a hang is worse than a crash. A crash frees the worker, and the row is retried once or twice before poison-detection parks it. A hang holds the worker indefinitely while the lease expires, the row returns to the ready state, and the next worker claims it.

With *N* analysis workers and a reliable hang, an adversary needs *N* poisoned files to stall the stage completely — **and the pipeline's own recovery mechanism performs the distribution.**

The system studied ran six analysis workers with a 20-minute lease and a poison threshold of three reaps. Six crafted files would have consumed the entire pool for an hour before the threshold parked them. Nothing prevents an operator from planting a hundred.

---

## 4. Case study: four defects

Measurements in this section come from the reproduction script (§9). Two environments were used: x86-64 Python 3.12, and aarch64 Python 3.10. Absolute timings differ; the growth ratios — the substantive claim — agree to within 2%.

### 4.1 Exponential backtracking in the decoder-chain matcher

The deobfuscator located decoder chains with the following pattern (Python `re`, `VERBOSE | DOTALL`):

```python
(?P<funcs>(?:@?\s*[A-Za-z_]\w*\s*\(\s*)+)   # one or more func(
(?P<q>['"])                                 # opening quote
(?P<body>(?:\\.|(?!(?P=q)).)*)              # literal body
(?P=q)                                      # closing quote
\s*\)+
```

The body alternation is ambiguous. `\\.` matches a backslash followed by any character; `(?!(?P=q)).` also matches a backslash, since a backslash is not the quote character. Any run of backslashes can therefore be partitioned between the two branches in exponentially many ways. When the closing quote is absent — so the overall match must ultimately fail — the engine explores that entire space before giving up.

**Trigger.** A PHP file containing `eval('`, a run of backslashes, and no closing quote. Roughly 38 bytes at *n*=30.

**Measured** (aarch64, Python 3.10):

| backslashes | original (s) | ratio | current (s) |
|---:|---:|---:|---:|
| 24 | 0.0800 | — | <0.001 |
| 26 | 0.2070 | ×2.59 | <0.001 |
| 28 | 0.5410 | ×2.61 | <0.001 |
| 64 | intractable | — | <0.001 |
| 200 | intractable | — | <0.001 |

Mean growth: **×2.60 per two additional backslashes**. Extrapolating from the measured curve: ≈5.5 hours at *n*=50, ≈657 hours at *n*=60. Nesting wrappers multiplies the effect — with the realistic prefix `eval(gzinflate(base64_decode('`, *n*=30 exceeded 40 s.

### 4.2 A quadratic defect introduced by the fix

The obvious repair makes the branches disjoint, so no input can be consumed by both:

```python
(?P<body>(?:\\.|[^'"\\]){0,2000000})
```

This is correct, and it eliminates the exponential case entirely: *n*=32 fell from seconds to below timer resolution, and *n*=200 stayed there.

It also introduced a new defect. The function-name group retained an unbounded `\w*`. `re.search()` retries at successive offsets, and inside a long body every retry allowed `\w*` to consume to end-of-string before backtracking one character at a time in search of `(`. That is O(*n*) work at O(*n*) offsets.

**Measured:**

| body chars | first fix (s) | ratio | current (s) | ratio |
|---:|---:|---:|---:|---:|
| 10,000 | 0.6429 | — | 0.0113 | — |
| 20,000 | 2.5486 | ×3.96 | 0.0229 | ×2.02 |

A clean quadratic at **×3.96 per doubling**, against linear **×2.02** after the second repair. Extrapolating the quadratic curve to a multi-megabyte file gives tens of hours for a single input — worse in practice than the exponential defect it replaced, because it requires no unusual bytes at all. A large file of alphanumerics after an `eval('` suffices.

**We report our own misdiagnosis as part of the finding.** Our first hypothesis was that the pattern was scanning across newlines; we changed `\s` to `[ \t]` and removed `DOTALL`. Measured effect: none — 10.75 s at 40,000 characters, unchanged. Only bounding the repetition to `\w{0,63}` restored linearity. Complexity defects resist reasoning-by-inspection. They need measurement, and that is why the reproduction script exists.

### 4.3 A timeout that cannot fire

A wall-clock budget was added to bound any residual pathology:

```python
with ThreadPoolExecutor(max_workers=1) as pool:
    future = pool.submit(_deobfuscate_inner, source, max_rounds)
    try:
        return future.result(timeout=timeout_s)
    except FuturesTimeoutError:
        log.error("Deobfuscation timed out after %d s", timeout_s)
        return source
```

This reads correctly and does nothing, for two independent reasons.

**First**, CPython's `re` does not release the GIL during matching. A runaway match in the worker thread holds the GIL for its full duration, so the calling thread is never scheduled to raise `TimeoutError`.

**Second**, even if the timeout did fire, `with ThreadPoolExecutor(...)` calls `shutdown(wait=True)` on exit. Returning from inside the `with` block blocks in `__exit__` until the runaway thread finishes. The timeout would delay the hang, not prevent it.

**Measured.** A 1.2 MB payload — below the file-size cap, therefore not skipped — with `timeout_s=3` was still running after 44 s, at which point the test was terminated.

A timeout that cannot fire is worse than no timeout, because it reads as protection during review and suppresses the question of whether protection exists.

### 4.4 Unbounded decompression

The archive-extraction layer was carefully written: it rejected absolute paths, path traversal, and symlink, hardlink and device members; it enforced file-count and total-uncompressed-size caps; and it counted bytes actually written rather than trusting declared sizes.

The deobfuscator then bypassed all of it:

```python
@_dec("gzinflate")
def _gzinflate(data: bytes) -> bytes:
    return zlib.decompress(data, -zlib.MAX_WBITS)   # no max_length
```

A base64 blob embedded in a PHP file never passes through the archive layer's accounting — it is a string inside a file, not an archive member. `zlib.decompress` without `max_length` inflates it fully into process memory, and the deobfuscation loop then iterates up to 25 rounds, each able to inflate again.

**Measured.** A raw-DEFLATE blob of 1,043,638 bytes expanding to 1 GB of nulls was accepted and inflated in full. The host systemd unit set no `MemoryMax`.

---

## 5. Aggregate impact

Each defect independently halts the analysis stage; combined with the reaper (§3.1), each becomes self-distributing across the worker pool.

The affected stage is the one producing the pipeline's distinguishing output. Ingest, triage and takedown continue; what stops is kit dissection, and therefore exfiltration-channel extraction, actor clustering and the published indicator feed.

From outside — and from most dashboards — the pipeline continues to look healthy. Analysis queue depth rises, which is observable in principle, but the system studied did not export worker metrics to its monitoring at all (§7.2). In practice the failure would have been silent.

---

## 6. Mitigations and evaluation

### 6.1 Isolation

Analysis now executes in a container launched per archive:

```
--network none                 no egress, no callback, no lateral movement
--read-only                    immutable root filesystem
--cap-drop ALL                 no capabilities
--security-opt no-new-privileges
--memory / --cpus              bounded (decompression bombs)
--pids-limit 128               bounded (fork bombs)
--tmpfs /tmp:noexec,nosuid     single size-capped writable path
subprocess timeout             bounded wall clock (parser hangs)
```

Podman is preferred over Docker so the worker needs no membership of the `docker` group, which is root-equivalent on the host. The image contains only the pure-Python analysis modules and their parsing dependencies — no database driver, no cloud SDK, no credentials — so a compromise finds nothing to exfiltrate and no route out.

**This is the only hard boundary.** Everything below is defence in depth.

### 6.2 A linear pattern

```python
(?P<funcs>(?:@?[ \t]*[A-Za-z_]\w{0,63}[ \t]*\([ \t]*){1,8})
(?P<q>['"])
(?P<body>(?:\\[^\n]|[^'"\\\n]){0,1000000})
(?P=q)
[ \t]*\)+
```

Three changes: disjoint body branches (eliminating §4.1), bounded function-name repetition (eliminating §4.2), and `[ \t]` with no `DOTALL` so a match attempt cannot cross a newline. Real decoder chains are single-line, so nothing legitimate is lost — verified in §6.5.

### 6.3 A timeout that works

The cooperative deadline is checked once per match rather than once per round, since a file with many small chains spends its budget in aggregate. Where the optional `regex` module is present it supplies a genuine per-call `timeout`, which the standard library lacks. The container's `subprocess` timeout remains the only guarantee holding unconditionally.

### 6.4 Bounded decompression

```python
d = zlib.decompressobj(-zlib.MAX_WBITS)
out = d.decompress(data, _MAX_DECODED)     # 32 MB
if d.unconsumed_tail:
    raise ValueError("decompression cap exceeded")
```

Applied to the raw-DEFLATE, zlib and gzip decoders, with a corresponding cap on base64 input length. The threshold for attempting deobfuscation at all was lowered from 5 MB to 2 MB.

### 6.5 Results

| Scenario | Before | After |
|---|---:|---:|
| 24 backslashes | 0.0800 s | <0.001 s |
| 28 backslashes | 0.5410 s | <0.001 s |
| 200 backslashes | intractable | <0.001 s |
| 10,000-char body | 0.6429 s | 0.0113 s |
| 20,000-char body | 2.5486 s | 0.0229 s |
| **Growth per doubling** | **×3.96 (quadratic)** | **×2.02 (linear)** |
| 2 MB single line (at cap) | tens of hours (extrap.) | **2.2820 s** |
| `timeout_s=2` on 1.5 MB | >44 s, no effect | **2.00 s** |
| 1 GB bomb via `gzinflate` | inflated in full | **`ValueError` in 0.079 s** |
| 1 GB bomb via `gzuncompress` | inflated in full | **`ValueError` in 0.093 s** |
| Legitimate compressed source | decoded | **decoded — unchanged** |

**End to end.** A deliberately hostile archive containing an 80-backslash ReDoS payload, a 300,000-character quadratic payload, a 512 MB decompression bomb, a file with live indicators, and a decoy results file:

```
Completed in 0.76 s, exit code 0
files inventoried: 5
victim-log paths noted: ['result.txt']
indicators extracted: 4

| telegram_token | 1234***:AAF-***                                |
| slack_webhook  | https://hooks.slack.com/services/T00000000/*** |
| url            | https://api.telegram.org/***                   |
```

Every indicator was still extracted. Hardening cost no analytical capability — a point verified explicitly, because a pattern that is safe but no longer matches real decoder chains would silently gut the pipeline's output, a worse outcome than the hang it replaced.

### 6.6 Regression tests

Sixteen tests assert these properties, three of them asserting **wall-clock complexity**: doubling the input must not more than 2.5× the time. Asserting timing in a test suite is unusual, and adopted deliberately — the property under test is asymptotic complexity, and there is no structural way to express it. The tolerance absorbs scheduler noise while failing clearly on quadratic behaviour, which shows ×4.

---

## 7. Discussion

### 7.1 The documented sandbox that never existed

The pipeline's README, architecture diagram, ethics policy, configuration module and `docker-compose.yml` all described analysis running inside a hardened container: `--network none`, non-root, read-only filesystem, bounded timeout. The ethics documentation listed "Never execute a kit" as a rule "enforced in code, not just policy," citing that container.

No code path launched it. A repository-wide search for container invocation returned exactly one hit: an unused configuration constant. The image's declared entrypoint referenced a Python module that did not exist, so the image could not have started. Four settings governing the sandbox's timeout, memory and CPU limits were read by nothing. Meanwhile `docker-compose.yml` mounted the Docker socket — root-equivalent access — into the worker "because the analyzer worker needs it," and the host provisioning script added the service account to the `docker` group for the same stated reason.

The net effect: a security guarantee existing only in prose, a dangerous privilege granted to support it, and no mechanism that would ever reveal the gap. This matters beyond one project, because the sandbox was the control that would have contained every defect in §4.

Our response was to make the guarantee **testable**. A unit test now asserts that each isolation flag appears in the constructed argument vector; another asserts that a missing container runtime raises rather than silently falling back to host-side analysis. The claim in the documentation and the flag in the code are now checked against each other by CI.

We suggest this generalises: *a security property stated in a README and not asserted by a test is a property you do not have.* It can be removed by refactoring, never implemented in the first place, or quietly disabled — and nothing will tell you.

### 7.2 Silent failure

Worker processes incremented Prometheus counters — stage duration, items processed, rows recovered — into per-process registries that nothing scraped and that were discarded at process exit. Only the API server exposed a metrics endpoint, and the API ran none of the pipeline stages. Every operational signal that would have distinguished "analysis is stalled" from "no kits collected today" was computed and thrown away.

An availability attack is only effective if it goes unnoticed. Instrumentation that is never exported is equivalent to no instrumentation — arguably worse, because reading the code gives the impression the system is observable.

### 7.3 Applicability

We expect this class in other tooling that parses adversary-authored content: phishing-kit analysers, PHP and JavaScript deobfuscators, malware unpackers, memory-forensics parsers, and log pipelines processing attacker-influenced fields. All share the defining property — the adversary chooses the input and benefits from the parser failing.

We do not yet have evidence for that expectation (§12).

---

## 8. Related work

This case study intersects with four distinct threads in security engineering and measurement: the characterisation of phishing infrastructure, algorithmic complexity attacks (specifically ReDoS), archive-extraction hardening, and the security of analysis tooling.

**Phishing-kit measurement and collection.** The pipeline architecture described in §2 builds directly on the measurement frameworks established by Oest et al. [1, 2] and Bijmans et al. [3]. Oest et al. demonstrated that phishing campaigns have extremely short operational lifespans and rely heavily on server-side cloaking (such as `.htaccess` filtering and User-Agent fingerprinting) to evade automated scanners [1]. To combat this, they developed the PhishFarm framework to empirically evaluate anti-phishing blacklists [2]. Similarly, Bijmans et al. developed robust fingerprinting methodologies to cluster phishing kits based on static code features, relying on TLS transparency logs to identify live infrastructure [3]. Outpost adopts this exact paradigm — using CT logs for discovery and static analysis for attribution — but our findings show that the static analysers themselves present a critical attack surface.

**Algorithmic complexity attacks and ReDoS.** Regular Expression Denial of Service (ReDoS) is a well-documented algorithmic complexity attack exploiting the backtracking engines of languages like JavaScript, Python, and Ruby [4, 5]. Crosby and Wallach formalised algorithmic complexity attacks in 2003, demonstrating how pathological inputs can force O(n) average-case algorithms into O(n²) or O(2^n) worst-case scenarios [4]. In the context of regex, this is typically caused by nested repetition operators (e.g., `(a+)+`) [5]. Our finding in §4 — an unbounded `\w*` in PHP function name extraction — represents a real-world manifestation of this vulnerability inside an intelligence-gathering pipeline, compounded by the Python GIL which prevented defensive timeouts from firing.

**Archive-extraction hardening.** Phishing kits are predominantly distributed as `.zip` or `.tar.gz` archives. The extraction of untrusted archives is a known risk vector for decompression bombs (zip bombs) and path traversal (zip-slip) [6]. While our pipeline's initial design bounded zlib decompression to mitigate zip bombs (§6), the logic was structurally flawed due to silent failures in the orchestrator. This highlights the gap between documented security policies and enforced constraints.

**Security of security tooling.** The central thesis of this report rests on the vulnerability of security tooling to adversarial inputs. While much literature exists on *evading* detection (e.g., malware packing, anti-sandboxing), there is significantly less focus on *attacking the analysis infrastructure itself* [7]. A threat-intel pipeline consumes hostile input by construction; our work demonstrates that an adversary can trivially convert this "pull-based" collection into an availability attack. By planting a 60-byte ReDoS booby-trap in an open directory, the adversary forces the collector to voluntarily download and execute a denial-of-service payload, neutralising the intelligence gathering operation entirely.

---

## 9. Reproducibility

Every measurement in §4 and §6 is regenerated by:

```bash
python3 paper/reproduce.py            # full run
python3 paper/reproduce.py --quick    # skip the slowest vulnerable cases
python3 paper/reproduce.py --json results.json
```

The script has no dependencies beyond the Python standard library, makes no network requests, and touches no third-party system. It pins the three historical patterns verbatim from the project's git history and measures them side by side, printing Markdown tables that match those above.

Vulnerable measurements that exceed a 30-second budget are abandoned and reported as such — that is the finding, not a failure of the script.

The regression suite in `tests/test_regressions.py` asserts the same properties as pass/fail conditions.

---

## 10. Ethics and disclosure

All defects reported here were found in the author's own software, tested against synthetic inputs generated locally on the author's own hardware. No third-party system was probed, no live phishing infrastructure was involved, and no victim data was accessed in producing any measurement in this report.

All four defects are fixed in the public repository. No embargo applies, since there is no third party to notify.

Where the survey in §12 identifies the same class in other projects, we will follow coordinated disclosure: private report to maintainers, a 90-day embargo extended on request where a fix is in progress, and CVE assignment through the appropriate CNA. Proof-of-concept inputs will be published only after fixes ship, and only as size-parameterised generators rather than ready-made payloads.

The wider pipeline from which this case study is drawn performs opportunistic collection against third-party hosts under a published scope-and-ethics policy with rate limits enforced in code. That collection is not part of this report, and none of the measurements here depended on it.

---

## 11. Limitations

**Single system.** Four defects in one codebase. We claim the threat model generalises; we have not shown the defects do.

**Author-evaluated.** The same person wrote the vulnerable code, found the defects, wrote the fixes and wrote this report. No independent review has occurred. Stated plainly because it bears on how much weight the findings carry.

**Extrapolated worst cases.** The multi-hour figures are extrapolations from measured growth rates, not observed runs. The growth rates themselves are measured, stable across multiple points, and reproducible.

**Two environments.** x86-64/Python 3.12 and aarch64/Python 3.10, Linux only. Regex backtracking is engine-specific; PCRE, RE2 and .NET behave differently, and RE2 is immune to §4.1 by construction.

**No adversary observed.** We show the attack is possible and cheap. We have no evidence any operator has attempted it. Whether the class is exploited in the wild is unknown.

---

## 12. Future work

**A survey.** Assemble a corpus of adversarial inputs — ReDoS, decompression bombs, zip-slip, path traversal, entity expansion, deeply nested structures — parameterised by size, and run it against open-source phishing-kit analysers, PHP deobfuscators and archive-processing utilities. Report which classes appear, at what rate, and whether isolation is used. This converts a case study into a measurement, and is the work that would make this report publishable at a peer-reviewed venue.

**Isolation as a norm.** Survey how much of this tooling analyses in-process versus in a sandbox, and what the practical barriers are.

**Beyond availability.** Data poisoning against clustering: an operator who can predict how indicators are hashed and grouped may be able to force merges between unrelated actors, or splits within their own infrastructure — corrupting attribution rather than merely stopping it.

---

## 13. Availability

| Artifact | Location |
|---|---|
| Source, audit and remediation reports | https://github.com/faseehfawaz/outpost |
| Live pipeline | https://outpost.heapleap.tech |
| Reproduction script | `paper/reproduce.py` |
| Regression suite | `tests/test_regressions.py` |
| Archived software release | *[Zenodo DOI — insert after upload]* |

---

## Acknowledgements

The author extends deep gratitude to the anonymous peer whose rigorous code review, architectural auditing, and invaluable guidance shaped both the remediation of these defects and the structure of this report.
