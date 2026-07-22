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

    # ---- database ---------------------------------------------------------
    db_url: PostgresDsn = Field(
        default="postgresql://pkintel:pkintel@localhost:5432/pkintel",
        description="Postgres DSN. Neon/Supabase free tier in prod.",
    )
    db_pool_min: int = Field(default=1)
    db_pool_max: int = Field(default=10)

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
    http_max_connections: int = Field(default=10)
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

    # ---- fingerprint / cluster -------------------------------------------
    cluster_jaccard_threshold: float = Field(default=0.6)
    cluster_min_shared_files: int = Field(default=3)

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
