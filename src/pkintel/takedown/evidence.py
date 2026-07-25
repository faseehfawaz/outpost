import base64
import hashlib
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def generate_sha256(content: bytes) -> str:
    """Generate SHA256 hash for given bytes."""
    return hashlib.sha256(content).hexdigest()

def build_evidence_package(
    url_id: int, 
    screenshot_path: Optional[str] = None, 
    dom_html: Optional[str] = None, 
    har_json: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Builds a structured evidence package for abuse email or API dispatch.
    
    Args:
        url_id (int): Database ID of the URL.
        screenshot_path (str, optional): Path to the screenshot file.
        dom_html (str, optional): HTML content of the page DOM.
        har_json (dict, optional): HAR data from network capture.
        
    Returns:
        Dict[str, Any]: Structured evidence package with base64 encoded attachments and hashes.
    """
    evidence = {
        "url_id": url_id,
        "attachments": []
    }
    
    if screenshot_path:
        try:
            with open(screenshot_path, "rb") as f:
                img_data = f.read()
                evidence["attachments"].append({
                    "filename": f"screenshot_{url_id}.png",
                    "content_type": "image/png",
                    "data_base64": base64.b64encode(img_data).decode('utf-8'),
                    "sha256": generate_sha256(img_data)
                })
        except Exception as e:
            logger.error(f"Failed to process screenshot evidence: {e}")

    if dom_html:
        dom_bytes = dom_html.encode('utf-8')
        evidence["attachments"].append({
            "filename": f"dom_{url_id}.html",
            "content_type": "text/html",
            "data_base64": base64.b64encode(dom_bytes).decode('utf-8'),
            "sha256": generate_sha256(dom_bytes)
        })

    if har_json:
        har_bytes = json.dumps(har_json).encode('utf-8')
        evidence["attachments"].append({
            "filename": f"network_{url_id}.har",
            "content_type": "application/json",
            "data_base64": base64.b64encode(har_bytes).decode('utf-8'),
            "sha256": generate_sha256(har_bytes)
        })
        
    return evidence
