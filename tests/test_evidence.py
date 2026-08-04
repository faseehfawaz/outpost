from pkintel.takedown.evidence import build_evidence_package


def test_build_evidence_package_empty():
    evidence = build_evidence_package(url_id=1)
    assert evidence["url_id"] == 1
    assert len(evidence["attachments"]) == 0


def test_build_evidence_package_with_data(tmp_path):
    screenshot_file = tmp_path / "screenshot.png"
    screenshot_file.write_bytes(b"fake image data")

    dom_html = "<html><body>Phish!</body></html>"
    har_json = {"log": {"entries": []}}

    evidence = build_evidence_package(
        url_id=42, screenshot_path=str(screenshot_file), dom_html=dom_html, har_json=har_json
    )

    assert evidence["url_id"] == 42
    assert len(evidence["attachments"]) == 3

    filenames = [att["filename"] for att in evidence["attachments"]]
    assert "screenshot_42.png" in filenames
    assert "dom_42.html" in filenames
    assert "network_42.har" in filenames

    for att in evidence["attachments"]:
        assert "data_base64" in att
        assert "sha256" in att
