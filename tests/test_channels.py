import pytest
from src.pkintel.takedown.channels import (
    dispatch_safe_browsing,
    dispatch_phishtank,
    dispatch_apwg,
    dispatch_netcraft,
    dispatch_aecert,
    dispatch_all_channels
)

def test_individual_dispatchers():
    url = "http://phish.example.com"
    assert dispatch_safe_browsing(url) is True
    assert dispatch_phishtank(url) is True
    assert dispatch_apwg(url, {"evidence": "data"}) is True
    assert dispatch_netcraft(url) is True
    assert dispatch_aecert(url, "Notice body") is True

def test_dispatch_all_channels():
    url = "http://phish.example.com"
    notice = {"body": "Malicious site notice"}
    evidence = {"url_id": 1, "attachments": []}
    
    channels = dispatch_all_channels(url, notice, evidence)
    assert "safe_browsing" in channels
    assert "phishtank" in channels
    assert "apwg" in channels
    assert "netcraft" in channels
    assert "aecert" in channels
