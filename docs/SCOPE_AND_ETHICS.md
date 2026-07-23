# Scope & Ethics

> This document is a control, not a disclaimer. Every module in this repository is
> written to obey it, and several of the constraints below are enforced in code
> (see the "Enforced by" notes). If you fork or extend this project, keep this
> file honest — the discipline it describes *is* the project.

## What this system is

`pkintel` is a **passive** phishing-kit intelligence pipeline. It:

1. Learns about phishing URLs from **public feeds** (Certificate Transparency,
   URLhaus, OpenPhish, urlscan.io, community GitHub lists).
2. Fetches those pages **politely** to decide whether they are phishing and which
   brand they imitate.
3. **Opportunistically collects kit archives that the attacker left publicly
   exposed** — an open directory listing, a `.zip` next to the deployed kit, an
   exposed results log.
4. **Statically dissects** collected kits inside a locked-down, no-network
   container to extract the attacker's exfiltration channels and code
   fingerprints. Kits are **never executed**.
5. **Clusters** kits into actor groups and publishes an intelligence dashboard,
   a redacted IOC feed, and files **takedowns**.

## What this system is **not**

It is not an offensive tool. It performs no exploitation, no brute forcing, no
fuzzing, no credential use, and no interaction with attacker infrastructure
beyond fetching what is already publicly served.

## The non-negotiables

These are copied verbatim into the README and are stated out loud to anyone who
asks what the project does.

### 1. Never execute a kit
Static analysis only, always inside the no-network container
(`--network none`, non-root, read-only root filesystem, CPU/memory caps,
timeout). We iteratively *decode* obfuscation with a decoder we wrote; we never
`eval`, include, or run attacker PHP.

*Enforced by:* `analyzer_container/` runs the analyzer with `network_mode: none`
and `read_only: true`; the deobfuscator (`analyzer/deobfuscate.py`) is a pure
string transform with no `exec`/`eval`.

### 2. Never use an extracted token
A Telegram bot token, Discord webhook, or SMTP credential found in a kit may be
**reported** to the relevant abuse desk. It may **never** be used to send a
request, read messages, or interact with the channel. Those channels contain
real victims' data, and touching them crosses from research into unauthorized
access.

*Enforced by:* extracted values are stored encrypted and only ever emitted into
an abuse report body; there is no code path in this repo that makes an outbound
request to an extracted indicator.

### 3. Never retain victim data
If we find a results log containing live credentials, we record **only its
existence and a hash** (`victim_log_sightings`), report it to the host and to
aeCERT (the UAE CERT), and delete the local copy. We do not read, parse, store,
or publish victim credentials.

*Enforced by:* the kit hunter never writes log-file *contents* to the DB; it
writes a `content_sha256` and byte count, then purges. See
`kithunter/logs.py`.

### 4. Redact publicly
The public site and IOC feed publish **token hashes and partial identifiers**
only. Full exfil values go **only** to abuse desks. Publishing a live C2
credential would simply hand it to the next attacker.

*Enforced by:* `redact.py` is the single path from raw indicator to any
public-facing string; the API never selects `full_value_encrypted`.

### 5. Passive collection only, rate-limited
No brute forcing, no fuzzing, no path enumeration beyond a short, fixed, polite
list, and a hard cap on attempts per host. One request every few seconds per
host. The servers are usually **hacked legitimate sites** — the owner is a
victim and we behave accordingly.

*Enforced by:* `http.py` throttles every request per host; the kit hunter has a
hard `kithunt_max_attempts_per_host` cap and a fixed candidate list (no
generated permutations).

## Legal footing

The UAE's cybercrime law (Federal Decree-Law No. 34 of 2021) is strict on
unauthorized access. This project is deliberately built so that a written record
(this document + the `audit_log` table) shows every action stayed on the passive
side of the line: we only ever retrieved content the server already offered to
any anonymous visitor, and we never authenticated, guessed, or interacted with
attacker channels.

## Responsible disclosure & contacts

- **Compromised legitimate host** → notify the host's RDAP/WHOIS abuse contact.
- **Live victim credentials sighted** → host + **aeCERT** (`aeCERT`, TDRA), then delete.
- **Telegram exfil token** → `abuse@telegram.org` (report only).
- **Malicious URL** → Google Safe Browsing + APWG.

## Data retention

| Data | Retained? | Notes |
|------|-----------|-------|
| Public feed URLs | Yes | public data |
| Kit archives | Yes, quarantined | never web-served, never executed |
| Attacker exfil channels | Yes, encrypted | reported to abuse desks; redacted in public |
| Victim credentials | **No** | existence + hash only, then deleted |
| Author strings / fingerprints | Yes | this is the research output |

## The point

Plenty of people can build a scraper. The value here is the discipline: being
able to articulate *why we did not pull the trigger* on a token sitting in our
own database. If a change to this repo would weaken any non-negotiable above,
that change does not ship.
