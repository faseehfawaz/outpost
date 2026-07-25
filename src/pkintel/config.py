"""Central configuration.

All runtime knobs live here and are populated from the environment (or a local
`.env`). Every subsystem imports :data:`settings`; nothing else reads os.environ
directly. Defaults are safe-for-development; the ethics-critical rate limits are
conservative on purpose.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PKINTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- environment ------------------------------------------------------
    env: str = Field(default="dev", description="dev | prod")
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=False, description="emit JSON logs (prod)")

    # ---- observability (Sentry + Datadog) ----------------------------------
    sentry_dsn: str = Field(default="", description="Sentry DSN for error tracking")
    sentry_traces_sample_rate: float = Field(default=0.3)
    dd_service: str = Field(default="outpost", description="Datadog service name")
    dd_env: str = Field(default="dev", description="Datadog environment tag")

    # ---- database ---------------------------------------------------------
    db_url: PostgresDsn = Field(
        default="postgresql://pkintel:pkintel@localhost:5432/pkintel",
        description="Postgres DSN. Neon/Supabase free tier in prod.",
    )
    db_pool_min: int = Field(default=1)
    db_pool_max: int = Field(default=20)
    # Bound both connection establishment and waiting for a pooled connection.
    # Unbounded, an unreachable DB hangs /health and /metrics for the OS TCP
    # timeout, which makes a blip look like a total outage exactly when you are
    # trying to diagnose it.
    db_connect_timeout_s: int = Field(default=5)
    db_pool_timeout_s: float = Field(default=10.0)

    # ---- object storage (kit archives) -----------------------------------
    # Cloudflare R2 speaks the S3 API. Archives are QUARANTINED here and are
    # NEVER placed on a web-served path or a box that runs PHP.
    r2_endpoint: str = Field(default="", description="R2 S3 endpoint URL")
    r2_bucket: str = Field(default="pkintel-kits")
    r2_access_key_id: str = Field(default="")
    r2_secret_access_key: str = Field(default="")
    # Local fallback so the pipeline runs with zero cloud deps in dev.
    local_storage_dir: str = Field(default="./.storage/kits")

    # ---- HTTP client / politeness ----------------------------------------
    user_agent: str = Field(
        default=(
            "pkintel-research/0.1 (+https://github.com/your-org/pkintel; "
            "passive phishing-kit research; contact abuse@yourdomain)"
        ),
        description="Honest, contactable UA. We are not hiding.",
    )
    http_timeout_s: float = Field(default=15.0)
    # Raised from 10 for the concurrent triage pool (see triage_workers). This
    # is a *total socket* cap, not a per-host one — per-host politeness is
    # enforced separately and unchanged by _HostThrottle in pkintel.http.
    http_max_connections: int = Field(default=256)
    # Per-host politeness: at most one request every N seconds to a given host.
    per_host_min_interval_s: float = Field(default=3.0)

    # ---- kit hunter (ethics-critical limits) ------------------------------
    # Hard caps that keep collection unambiguously passive. See SCOPE_AND_ETHICS.
    kithunt_max_attempts_per_host: int = Field(default=12)
    kithunt_request_interval_s: float = Field(default=4.0)
    kithunt_max_archive_bytes: int = Field(default=200 * 1024 * 1024)  # 200 MB
    kithunt_archive_names: list[str] = Field(
        default_factory=lambda: [
            "kit.zip",
            "login.zip",
            "index.zip",
            "www.zip",
            "backup.zip",
            "mail.zip",
            "office.zip",
            "next.zip",
            "auth.zip",
        ]
    )
    kithunt_log_names: list[str] = Field(
        default_factory=lambda: ["log.txt", "result.txt", "data.txt", "results.txt", "logs.txt"]
    )

    # ---- analyzer (sandbox) ----------------------------------------------
    analyzer_image: str = Field(default="pkintel-analyzer:latest")
    analyzer_timeout_s: int = Field(default=120)
    analyzer_mem_limit: str = Field(default="512m")
    analyzer_cpu_limit: str = Field(default="1.0")
    analyzer_max_uncompressed_bytes: int = Field(default=500 * 1024 * 1024)
    analyzer_max_files: int = Field(default=20000)
    analyzer_max_deobf_rounds: int = Field(default=25)

    # ---- indicator encryption (ethics-critical) --------------------------
    # Fernet key(s) for indicators.full_value_encrypted. Comma-separated to
    # rotate: the FIRST key encrypts, ANY key decrypts. If unset we fail CLOSED
    # (store nothing) rather than degrade to plaintext — see pkintel.crypto.
    # Generate:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    indicator_enc_key: str = Field(default="", description="Fernet key(s), comma-separated")

    # ---- concurrency (tuned for 12 threads / 32 GB) ----------------------
    # Triage and ingest are I/O-bound: threads spend their life in socket wait,
    # so we run far more than we have cores. The per-host throttle in
    # pkintel.http is unchanged and still enforced — concurrency happens across
    # DIFFERENT hosts, never against the same one. No ethics cap is relaxed.
    triage_workers: int = Field(default=64, description="Concurrent triage fetches")
    ingest_workers: int = Field(default=8, description="Concurrent feed adapters")
    kithunt_workers: int = Field(default=6, description="Concurrent kit hunts (rate-limited)")
    analyzer_workers: int = Field(default=6, description="Concurrent sandbox analyses (CPU-bound)")
    takedown_workers: int = Field(default=8, description="Concurrent takedown dispatches")

    # ---- host enrichment (feeds the pivot graph) -------------------------
    # Resolves confirmed-phish hosts to IPs, maps the origin ASN, and
    # fingerprints the served TLS certificate. Without this the pivot graph's
    # two strongest signals (shared_cert, shared_ip) have no data to work with.
    enrich_enabled: bool = Field(default=True)
    enrich_workers: int = Field(default=32, description="Concurrent host enrichments")
    enrich_dns_timeout_s: float = Field(default=5.0)
    enrich_tls_timeout_s: float = Field(default=8.0)
    enrich_asn_enabled: bool = Field(
        default=True, description="Team Cymru DNS IP-to-ASN lookup (no API key required)"
    )
    # Attacker infrastructure rotates fast; enrichment older than this links
    # current hosts to stale IPs, which corrupts the pivot graph rather than
    # merely leaving it incomplete.
    enrich_ttl_days: int = Field(default=7, description="Re-enrich hosts older than this")

    # ---- work-queue reaper (stuck-row recovery) --------------------------
    # A worker killed mid-batch leaves rows pinned in a busy state forever.
    # The reaper returns any row whose lease has expired. Lease must exceed the
    # slowest legitimate run of that stage or we reap live work.
    reaper_enabled: bool = Field(default=True)
    reaper_lease_triage_s: int = Field(default=900)  # 15 min
    reaper_lease_kithunt_s: int = Field(default=1800)  # 30 min (12 probes x 4s + downloads)
    reaper_lease_analyze_s: int = Field(default=1200)  # 20 min
    reaper_lease_takedown_s: int = Field(default=600)  # 10 min
    reaper_lease_enrich_s: int = Field(default=600)  # 10 min (DNS + one TLS handshake)
    reaper_max_reaps: int = Field(
        default=3, description="After N reaps a row is poison; park it in 'error'."
    )

    # ---- deep triage: headless browser ------------------------------------
    # Most modern kits are JS-rendered or cloaked; a raw httpx.get sees nothing.
    # Chromium caches go on tmpfs (render_tmpfs_dir) so 8 browsers do not grind
    # a SATA SSD — we have the RAM to spare.
    render_enabled: bool = Field(default=True)
    render_browsers: int = Field(default=6, description="Concurrent Chromium contexts")
    render_timeout_s: float = Field(default=20.0)
    # /dev/shm is tmpfs (RAM), which is the point: eight Chromium instances
    # writing profile + cache to a SATA SSD would queue behind each other and
    # age the drive for nothing. Not a "temp file" security issue — the path is
    # fixed, not attacker-influenced, and holds only browser scratch data.
    render_tmpfs_dir: str = Field(default="/dev/shm/outpost-render")  # noqa: S108
    # On Arch, point this at the pacman-installed browser (/usr/bin/chromium)
    # and skip Playwright's 400 MB bundled download entirely. Empty = use the
    # bundled browser.
    render_executable: str = Field(default="")
    render_screenshot_dir: str = Field(default="/opt/heapleap/.storage/screenshots")
    # Only render candidates that already look interesting — rendering every URL
    # would waste the browser pool on dead 404s.
    render_min_score: int = Field(default=10)

    # ---- cloaking detection (multi-persona fetch) ------------------------
    cloak_detect_enabled: bool = Field(default=True)
    cloak_diff_threshold: float = Field(
        default=0.35, description="Normalised content distance that counts as cloaking"
    )

    # ---- local LLM tie-breaker (Ollama) ----------------------------------
    # Applied ONLY to the ambiguous score band, where the false negatives live.
    # Running it on every URL would waste the box; running it on none leaves
    # recall on the table.
    llm_enabled: bool = Field(default=False, description="Enable local LLM adjudication")
    llm_endpoint: str = Field(default="http://127.0.0.1:11434")
    llm_model: str = Field(default="llama3.1:8b-instruct-q4_K_M")
    llm_timeout_s: float = Field(default=45.0)
    llm_band_low: int = Field(default=20, description="Adjudicate scores >= this")
    llm_band_high: int = Field(default=45, description="Adjudicate scores <= this")
    llm_max_html_chars: int = Field(default=12000)

    # ---- certstream firehose ---------------------------------------------
    # Replaces crt.sh polling (slow, rate-limited, frequent 502s). Live cert
    # issuance means we see a lookalike domain minutes after it is registered —
    # often before the phishing page is even served.
    certstream_enabled: bool = Field(default=True)
    certstream_reconnect_s: float = Field(default=5.0)
    typosquat_enabled: bool = Field(default=True)
    typosquat_max_edit_distance: int = Field(default=2)

    # ---- takedown verification & escalation ------------------------------
    # Without this a takedown is fire-and-forget and "40 notices filed" proves
    # nothing. With it we can report confirmed kills and median time-to-death.
    takedown_verify_enabled: bool = Field(default=True)
    takedown_verify_first_s: int = Field(default=6 * 3600)
    takedown_verify_interval_s: int = Field(default=12 * 3600)
    takedown_max_verifications: int = Field(default=8)
    takedown_escalate_after_s: int = Field(default=48 * 3600)

    # ---- API security -----------------------------------------------------
    # The API is internet-facing. "*" origins with credentials is an invalid
    # CORS combo browsers reject outright, and there was no auth or rate limit.
    api_cors_origins: list[str] = Field(
        default_factory=lambda: ["https://outpost.heapleap.tech", "http://localhost:8000"]
    )
    api_key: str = Field(default="", description="If set, required for write/admin routes")
    api_rate_limit_per_min: int = Field(default=120)

    # ---- fingerprint / cluster -------------------------------------------
    cluster_jaccard_threshold: float = Field(default=0.6)
    cluster_min_shared_files: int = Field(default=3)
    # Infrastructure pivot: link hosts sharing IP/ASN/cert/favicon so campaigns
    # cluster from URLs alone, without ever landing a kit archive.
    pivot_enabled: bool = Field(default=True)
    pivot_max_hosts_per_ip: int = Field(
        default=200, description="Above this an IP is shared hosting, not a campaign — skip it."
    )
    pivot_max_hosts_per_asn: int = Field(default=5000)

    # ---- triage scoring ---------------------------------------------------
    triage_phish_threshold: int = Field(default=35, description="0-100 score to flag as phish")

    # ---- brands we prioritise (UAE-first) --------------------------------
    priority_brands: list[str] = Field(
        default_factory=lambda: [
            "Emirates NBD",
            "Emirates Islamic",
            "ADCB",
            "FAB",
            "Mashreq",
            "RTA",
            "Etisalat",
            "du",
            "Dubai Police",
            "ADNOC",
            "DEWA",
            "Emirates",
            "Emirates Post",
            "UAE PASS",
        ]
    )

    # ---- takedown ---------------------------------------------------------
    takedown_from_email: str = Field(default="security@heapleap.tech")
    takedown_dry_run: bool = Field(
        default=True, description="If true, generate reports but do not send."
    )
    takedown_override_recipient: str = Field(
        default="", description="Redirect all outbound takedowns to this email for testing."
    )
    smtp_host: str = Field(default="", description="SMTP server host, e.g. smtp.gmail.com")
    smtp_port: int = Field(default=587, description="SMTP server port (587 for TLS, 465 for SSL)")
    smtp_user: str = Field(default="", description="SMTP login username")
    smtp_pass: str = Field(default="", description="SMTP login password / app password")
    smtp_use_tls: bool = Field(default=True)
    gsb_api_key: str = Field(default="", description="Google Safe Browsing")

    # ---- feeds (all optional; empty => adapter is skipped) ----------------
    urlhaus_enabled: bool = Field(default=True)
    openphish_enabled: bool = Field(default=True)
    urlscan_api_key: str = Field(default="")
    certstream_url: str = Field(default="wss://certstream.calidog.io/")
    ct_enabled: bool = Field(default=True)

    @field_validator("cluster_jaccard_threshold")
    @classmethod
    def _valid_jaccard(cls, v: float) -> float:
        if not 0.0 < v <= 1.0:
            raise ValueError("cluster_jaccard_threshold must be in (0, 1]")
        return v

    @property
    def db_dsn(self) -> str:
        return str(self.db_url)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
