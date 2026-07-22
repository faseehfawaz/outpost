from pkintel.takedown.rdap import (
    parse_rdap_abuse,
    parse_rdap_asn,
    parse_rdap_registrar,
    registrable_domain,
)
from pkintel.takedown.templates import host_abuse_report


def test_registrable_domain():
    assert registrable_domain("login.bank.co.ae") == "bank.co.ae"
    assert registrable_domain("sub.example.com") == "example.com"
    assert registrable_domain("1.2.3.4") is None


def test_parse_rdap_abuse():
    data = {
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@example.com"]]],
            }
        ]
    }
    assert parse_rdap_abuse(data) == "abuse@example.com"


def test_parse_rdap_registrar():
    data = {
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
            }
        ]
    }
    assert parse_rdap_registrar(data) == "Example Registrar"


def test_parse_rdap_asn():
    data = {"startAutnum": 12345, "name": "EXAMPLE-AS"}
    assert parse_rdap_asn(data) == (12345, "EXAMPLE-AS")


def test_host_abuse_report():
    subject, body = host_abuse_report("http://example.com/login", {}, {})
    assert "defang" in body.lower() or "redact" in body.lower()
