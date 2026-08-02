"""Local LLM Adjudication for Borderline Triage Scores via Ollama.

Evaluates URLs in the ambiguous score band (20 <= score <= 45) to rescue false
negatives. Uses structured JSON generation from local Ollama models (e.g. qwen2.5:3b).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)


def evaluate_borderline_url(url: str, html_snippet: str, score: int) -> dict[str, Any]:
    """Evaluates a borderline URL using a local LLM synchronously.

    Args:
        url: The URL under evaluation.
        html_snippet: HTML content snippet (truncated).
        score: The static/initial triage score.

    Returns:
        Dict with 'is_phishing' (bool), 'confidence' (float), 'reason' (str), or empty dict on failure.
    """
    if not (settings.llm_band_low <= score <= settings.llm_band_high):
        return {}

    snippet = html_snippet[: settings.llm_max_html_chars]
    endpoint = f"{settings.llm_endpoint.rstrip('/')}/api/generate"

    prompt = (
        f"Analyze the following URL and HTML snippet to determine if it is a phishing page.\n"
        f"URL: {url}\n"
        f"HTML: {snippet}\n\n"
        f"Respond ONLY in valid JSON format with the following keys:\n"
        f'- "is_phishing": boolean\n'
        f'- "confidence": float between 0.0 and 1.0\n'
        f'- "reason": string explaining the verdict\n'
    )

    payload = {
        "model": settings.llm_model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }

    try:
        with httpx.Client(timeout=settings.llm_timeout_s) as client:
            resp = client.post(endpoint, json=payload)
            if resp.status_code != 200:
                log.warning("llm_http_error", status=resp.status_code, url=url)
                return {}

            data = resp.json()
            resp_text = data.get("response", "{}")
            verdict = json.loads(resp_text)

            if isinstance(verdict, dict) and "is_phishing" in verdict:
                return {
                    "is_phishing": bool(verdict.get("is_phishing", False)),
                    "confidence": float(verdict.get("confidence", 0.5)),
                    "reason": str(verdict.get("reason", "LLM evaluation")),
                }
            log.warning("llm_invalid_format", raw=resp_text, url=url)
            return {}

    except Exception as e:
        log.warning("llm_evaluation_error", url=url, error=str(e))
        return {}
