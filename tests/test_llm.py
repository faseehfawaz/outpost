import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from src.pkintel.triage.llm import evaluate_borderline_url

@pytest.mark.asyncio
async def test_evaluate_borderline_url_out_of_range():
    # Score below 20
    res = await evaluate_borderline_url("http://example.com", "<html></html>", 19)
    assert res == {}

    # Score above 45
    res = await evaluate_borderline_url("http://example.com", "<html></html>", 46)
    assert res == {}

@pytest.mark.asyncio
@patch('src.pkintel.triage.llm.httpx.AsyncClient.post')
async def test_evaluate_borderline_url_success(mock_post):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "response": "{\"is_phishing\": true, \"confidence\": 0.9, \"reason\": \"Looks malicious\"}"
    }
    mock_response.raise_for_status = lambda: None
    mock_post.return_value = mock_response

    res = await evaluate_borderline_url("http://example.com", "<html></html>", 30)
    assert res == {"is_phishing": True, "confidence": 0.9, "reason": "Looks malicious"}

@pytest.mark.asyncio
@patch('src.pkintel.triage.llm.httpx.AsyncClient.post')
async def test_evaluate_borderline_url_error(mock_post):
    mock_post.side_effect = Exception("Network error")
    res = await evaluate_borderline_url("http://example.com", "<html></html>", 30)
    assert res == {}
