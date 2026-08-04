from unittest.mock import MagicMock, patch

from pkintel.triage.llm import evaluate_borderline_url


def test_evaluate_borderline_url_out_of_range():
    # Score below band
    res = evaluate_borderline_url("http://example.com", "<html></html>", 10)
    assert res == {}

    # Score above band
    res = evaluate_borderline_url("http://example.com", "<html></html>", 95)
    assert res == {}


@patch("pkintel.triage.llm.httpx.Client.post")
def test_evaluate_borderline_url_success(mock_post):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": '{"is_phishing": true, "confidence": 0.9, "reason": "Looks malicious"}'
    }
    mock_post.return_value = mock_response

    res = evaluate_borderline_url("http://example.com", "<html></html>", 30)
    assert res == {"is_phishing": True, "confidence": 0.9, "reason": "Looks malicious"}


@patch("pkintel.triage.llm.httpx.Client.post")
def test_evaluate_borderline_url_error(mock_post):
    mock_post.side_effect = Exception("Network error")
    res = evaluate_borderline_url("http://example.com", "<html></html>", 30)
    assert res == {}
