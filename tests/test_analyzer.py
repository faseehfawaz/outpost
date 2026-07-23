import pytest

from pkintel.analyzer.deobfuscate import deobfuscate, is_obfuscated
from pkintel.analyzer.safe_extract import UnsafeArchiveError, extract_archive


def test_extract_archive_normal(make_zip, tmp_path):
    zip_path = tmp_path / "test.zip"
    make_zip(zip_path, {"test.txt": b"hello"})
    dest = tmp_path / "dest"
    res = extract_archive(zip_path, dest, 10, 1000)
    assert len(res) == 1
    assert (dest / "test.txt").read_bytes() == b"hello"


def test_extract_archive_zip_slip(tmp_path, zip_slip_bytes):
    zip_path = tmp_path / "slip.zip"
    zip_path.write_bytes(zip_slip_bytes)
    dest = tmp_path / "dest"
    with pytest.raises(UnsafeArchiveError):
        extract_archive(zip_path, dest, 10, 1000)


def test_extract_archive_bomb_guard(make_zip, tmp_path):
    zip_path = tmp_path / "bomb.zip"
    make_zip(zip_path, {"large.txt": b"0" * 2000})
    dest = tmp_path / "dest"
    with pytest.raises(UnsafeArchiveError):
        extract_archive(zip_path, dest, 10, 1000)


def test_deobfuscate_base64():
    text = "eval(base64_decode('aGVsbG8='))"
    assert deobfuscate(text, 1) == "hello"


def test_deobfuscate_gzinflate():
    # Placeholder for gzinflate test
    pass


def test_is_obfuscated():
    assert is_obfuscated("eval(base64_decode('aGVsbG8='))") is True
    assert is_obfuscated("echo 'clean code';") is False
