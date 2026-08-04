from unittest.mock import MagicMock, patch

from pkintel.takedown.channels import (
    dispatch_aecert,
    dispatch_all_channels,
    dispatch_apwg,
    dispatch_netcraft,
    dispatch_phishtank,
    dispatch_safe_browsing,
)


@patch("pkintel.takedown.channels.httpx.Client.post")
@patch("pkintel.takedown.channels.send_takedown_email")
def test_individual_dispatchers(mock_send_email, mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    url = "http://phish.example.com"
    assert dispatch_safe_browsing(url) is True
    assert dispatch_phishtank(url) is True
    assert dispatch_netcraft(url) is True
    assert dispatch_aecert(url, "Notice body") is True
    assert dispatch_apwg(url, {"attachments": []}) is True


@patch("pkintel.takedown.channels.httpx.Client.post")
@patch("pkintel.takedown.channels.send_takedown_email")
def test_dispatch_all_channels(mock_send_email, mock_post):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_post.return_value = mock_resp

    url = "http://phish.example.com"
    notice = {"body": "Malicious site notice"}
    evidence = {"url_id": 1, "attachments": []}

    channels = dispatch_all_channels(url, notice, evidence)
    assert "safe_browsing" in channels
    assert "phishtank" in channels
    assert "apwg" in channels
    assert "netcraft" in channels
    assert "aecert" in channels
