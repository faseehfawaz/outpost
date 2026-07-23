"""Object storage for collected kit archives.

Kits are QUARANTINED here: an S3-compatible bucket (Cloudflare R2 in prod) or a
local directory in dev. Non-negotiable placement rule — this store is NEVER on a
web-served path and NEVER on a box that executes PHP. The analyzer pulls bytes
from here into a no-network container.
"""

from __future__ import annotations

import os
from pathlib import Path

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)


class Storage:
    """Minimal put/get over either R2 (S3 API) or the local filesystem."""

    def __init__(self) -> None:
        self._use_r2 = bool(settings.r2_endpoint and settings.r2_access_key_id)
        self._client = None
        if self._use_r2:
            import boto3

            self._client = boto3.client(
                "s3",
                endpoint_url=settings.r2_endpoint,
                aws_access_key_id=settings.r2_access_key_id,
                aws_secret_access_key=settings.r2_secret_access_key,
                region_name="auto",
            )
            log.info("storage_backend", backend="r2", bucket=settings.r2_bucket)
        else:
            Path(settings.local_storage_dir).mkdir(parents=True, exist_ok=True)
            log.info("storage_backend", backend="local", dir=settings.local_storage_dir)

    def key_for(self, sha256: str) -> str:
        # sharded by hash prefix; quarantine namespace makes intent explicit
        return f"quarantine/{sha256[:2]}/{sha256[2:4]}/{sha256}.zip"

    def put(self, sha256: str, data: bytes) -> str:
        key = self.key_for(sha256)
        if self._use_r2:
            self._client.put_object(
                Bucket=settings.r2_bucket,
                Key=key,
                Body=data,
                ContentType="application/octet-stream",
                # defense-in-depth: never let a bucket serve these
                Metadata={"quarantine": "true"},
            )
        else:
            dest = Path(settings.local_storage_dir) / key
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            os.chmod(dest, 0o600)
        log.info("kit_stored", key=key, size=len(data))
        return key

    def get(self, key: str) -> bytes:
        if self._use_r2:
            resp = self._client.get_object(Bucket=settings.r2_bucket, Key=key)
            return resp["Body"].read()
        return (Path(settings.local_storage_dir) / key).read_bytes()

    def local_path(self, key: str) -> Path | None:
        """Return an on-disk path for the key, materialising from R2 if needed.

        The analyzer needs a real file to mount read-only into the container.
        """
        if not self._use_r2:
            return Path(settings.local_storage_dir) / key
        tmp = Path(settings.local_storage_dir) / key
        tmp.parent.mkdir(parents=True, exist_ok=True)
        if not tmp.exists():
            tmp.write_bytes(self.get(key))
            os.chmod(tmp, 0o600)
        return tmp


_storage: Storage | None = None


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage
