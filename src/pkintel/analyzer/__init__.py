"""
Analyzer subsystem for the pkintel phishing-kit intelligence pipeline.
"""

def run_once(worker_id: str = "analyze-1", limit: int = 5) -> int:
    """Run the analyzer pipeline for a batch of kits."""
    from pkintel.analyzer.runner import run_once as _run_once
    return _run_once(worker_id, limit)
