from unittest.mock import MagicMock, patch

from pkintel.takedown.forms import identify_providers, submit_abuse_form


def test_identify_providers_matching():
    # Cloudflare matches
    cf_host = {
        "registrar": "Cloudflare, Inc.",
        "asn_name": "CLOUDFLARENET",
        "asn": 13335,
        "abuse_email": "abuse@cloudflare.com",
    }
    assert "cloudflare" in identify_providers(cf_host)

    # GoDaddy matches
    gd_host = {
        "registrar": "GoDaddy.com, LLC",
        "asn_name": "GoDaddy LLC",
        "asn": 26496,
        "abuse_email": "abuse@godaddy.com",
    }
    assert "godaddy" in identify_providers(gd_host)

    # Unknown provider
    unknown_host = {
        "registrar": "Some Unknown Registrar",
        "asn_name": "Unknown ASN",
        "asn": 99999,
        "abuse_email": "abuse@unknown.com",
    }
    assert identify_providers(unknown_host) == []


@patch("pkintel.takedown.forms.submit_via_playwright")
@patch("pkintel.takedown.forms.submit_via_http_post")
@patch("pkintel.takedown.forms.submit_via_api")
def test_submit_abuse_form_routing(mock_api, mock_post, mock_playwright):
    mock_playwright.return_value = True
    mock_post.return_value = True
    mock_api.return_value = True

    # Cloudflare routes to Playwright
    res_cf = submit_abuse_form("cloudflare", "http://phish.com", "Subject", "Body")
    assert res_cf is True
    mock_playwright.assert_called_once()

    # Google Safe Browsing routes to HTTP POST
    res_gsb = submit_abuse_form("google_safebrowsing", "http://phish.com", "Subject", "Body")
    assert res_gsb is True
    mock_post.assert_called_once()

    # Netcraft routes to API JSON
    res_net = submit_abuse_form("netcraft", "http://phish.com", "Subject", "Body")
    assert res_net is True
    mock_api.assert_called_once()
