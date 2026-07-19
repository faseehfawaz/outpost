"""Shared domain models (Pydantic v2).

These are the in-process value types passed between subsystems and returned by
the API. They intentionally mirror — but are not identical to — the SQL tables:
the DB has bookkeeping columns (locks, states) the domain layer doesn't care
about, and the domain layer has computed/redacted views the DB doesn't store.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    telegram_token = "telegram_token"
    telegram_chat = "telegram_chat"
    discord_webhook = "discord_webhook"
    email = "email"
    smtp = "smtp"
    url = "url"


class EdgeReason(str, Enum):
    shared_exfil = "shared_exfil"
    jaccard = "jaccard"
    shared_antibot = "shared_antibot"
    shared_author = "shared_author"


class TriageResult(BaseModel):
    is_phish: bool
    score: int = Field(ge=0, le=100)
    brand: str | None = None
    reasons: list[str] = Field(default_factory=list)
    favicon_mmh3: int | None = None
    logo_phash: str | None = None
    http_status: int | None = None
    is_live: bool | None = None


class InventoryFile(BaseModel):
    path: str
    sha256: str
    size: int
    mime: str | None = None
    tlsh: str | None = None
    normalized_token_hash: str | None = None
    is_obfuscated: bool = False


class Indicator(BaseModel):
    type: IndicatorType
    value_hash: str
    redacted_display: str
    full_value: str | None = Field(default=None, repr=False)  # never logged
    confidence: float = 1.0
    found_in_path: str | None = None
    meta: dict = Field(default_factory=dict)


class Fingerprint(BaseModel):
    fileset_hash: str | None = None
    antibot_hash: str | None = None
    token_hash: str | None = None
    author_strings: list[str] = Field(default_factory=list)
    file_sha_set: list[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Everything the sandbox analyzer produces for one kit. Emitted as JSON on
    the analyzer container's stdout and ingested by the host-side worker."""

    ok: bool
    error: str | None = None
    file_count: int = 0
    files: list[InventoryFile] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    fingerprint: Fingerprint = Field(default_factory=Fingerprint)
    victim_log_paths: list[str] = Field(default_factory=list)  # existence only


# ---- API response models --------------------------------------------------
class ActorCard(BaseModel):
    id: int
    label: str
    kit_count: int
    brands: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    notes: str | None = None


class IOCEntry(BaseModel):
    kind: str
    value: str          # redacted public value or hash
    kit_sha256: str
    actor_label: str | None = None
    brand: str | None = None
    first_seen: datetime | None = None
