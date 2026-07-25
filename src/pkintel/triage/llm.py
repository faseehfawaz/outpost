import httpx
import json
import logging

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3" # Or qwen:8b

async def evaluate_borderline_url(url: str, html_snippet: str, score: int) -> dict:
    """
    Evaluates a borderline URL using a local LLM if the score is between 20 and 45.
    
    Args:
        url (str): The URL to evaluate.
        html_snippet (str): A snippet of the HTML content.
        score (int): The initial triage score.
        
    Returns:
        dict: A dictionary containing 'is_phishing', 'confidence', and 'reason'.
    """
    if not (20 <= score <= 45):
        return {}

    prompt = f"""
    Analyze the following URL and HTML snippet to determine if it is a phishing page.
    URL: {url}
    HTML: {html_snippet}
    
    Respond ONLY in valid JSON format with the following keys:
    - "is_phishing": boolean
    - "confidence": float between 0.0 and 1.0
    - "reason": string explaining the verdict
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(OLLAMA_URL, json=payload)
            response.raise_for_status()
            
            data = response.json()
            response_text = data.get("response", "{}")
            
            # Parse the JSON response from the LLM
            verdict = json.loads(response_text)
            
            # Validate expected keys
            if all(k in verdict for k in ("is_phishing", "confidence", "reason")):
                return verdict
            else:
                logger.warning("LLM response missing expected keys: %s", verdict)
                return {}
                
    except Exception as e:
        logger.error(f"Error evaluating URL {url} with LLM: {str(e)}")
        return {}
