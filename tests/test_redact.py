from pkintel.redact import redact, sha256_hex


def test_redact():
    assert redact('email', 'foo@bar.com').endswith('bar.com')

def test_sha256_hex():
    assert sha256_hex(b'hello') == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
