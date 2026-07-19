import pytest
from pkintel.kithunter.paths import walk_up_dirs, archive_candidates
from pkintel.kithunter.opendir import is_open_directory, parse_listing, find_archives
from pkintel.kithunter.collect import looks_like_archive

def test_walk_up_dirs():
    assert walk_up_dirs('https://host/a/b/login.php') == ['https://host/a/b/', 'https://host/a/', 'https://host/']

def test_archive_candidates():
    candidates = archive_candidates('https://host/a/', ['kit.zip'])
    # archive_candidates yields dir-name guesses (a.zip) plus the provided names
    assert 'https://host/a/a.zip' in candidates
    assert 'https://host/a/kit.zip' in candidates

def test_is_open_directory():
    assert is_open_directory('<title>Index of /</title>') is True
    assert is_open_directory('<title>Login</title>') is False

def test_looks_like_archive():
    assert looks_like_archive(b'PK\x03\x04') is True
    assert looks_like_archive(b'<html>') is False
    assert looks_like_archive(b'\x1f\x8b\x08') is True

def test_parse_listing():
    html = '<a href="foo.zip">foo.zip</a>'
    assert parse_listing(html, 'https://host/') == ['https://host/foo.zip']

def test_find_archives():
    links = ['https://host/foo.zip', 'https://host/bar.html']
    assert find_archives(links) == ['https://host/foo.zip']
