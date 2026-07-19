#!/usr/bin/env python3
"""
Simple script to run analysis on an archive and print the result as JSON.
"""
import sys
import json
from pathlib import Path

from pkintel.analyzer.safe_extract import extract_archive
from pkintel.analyzer.inventory import process_inventory
from pkintel.analyzer.deobfuscate import deobfuscate
from pkintel.analyzer.indicators import extract_indicators
from pkintel.config import settings

def main():
    if len(sys.argv) < 3:
        print("Usage: run_analysis.py <archive_path> <output_dir>")
        sys.exit(1)
        
    archive_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    if not archive_path.exists():
        print(f"Archive not found: {archive_path}")
        sys.exit(1)
        
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Extract
        extracted_files = extract_archive(
            archive_path,
            output_dir,
            max_files=settings.analyzer_max_files,
            max_uncompressed_bytes=settings.analyzer_max_uncompressed_bytes
        )
        
        # Inventory
        inventory, fingerprint = process_inventory(extracted_files, output_dir)
        
        # Indicators
        all_indicators = []
        for file_path in extracted_files:
            if file_path.suffix.lower() == '.php':
                text = file_path.read_text(errors='ignore')
                deobf_text = deobfuscate(text, max_rounds=settings.analyzer_max_deobf_rounds)
                
                rel_path = str(file_path.relative_to(output_dir))
                file_inds = extract_indicators(deobf_text, rel_path)
                all_indicators.extend(file_inds)
                
        # Build JSON output
        result = {
            "inventory": [f.__dict__ for f in inventory], # Adjust if using pydantic
            "fingerprint": fingerprint.__dict__,
            "indicators": [i.__dict__ for i in all_indicators]
        }
        
        print(json.dumps(result, default=str))
        sys.exit(0)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
