import json
import os

import httpx

# Configure production DB DSN
os.environ["PKINTEL_DB_URL"] = (
    "postgresql://neondb_owner:npg_WKymvO6xETn4@ep-still-violet-asnnoi3n.c-4.eu-central-1.aws.neon.tech/neondb?sslmode=require"
)
os.environ["PKINTEL_TRIAGE_PHISH_THRESHOLD"] = "35"

from pkintel.config import settings
from pkintel.db import connection
from pkintel.triage.runner import _UPDATE_TRIAGED, _process_one


def main():
    priority_brands = list(settings.priority_brands)
    priority_lower = {b.strip().lower() for b in priority_brands}

    # Query the URLs we want to prioritize
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, url FROM urls 
                WHERE triage_state = 'new' 
                AND url IN (
                    'https://mymail.dewa.gov.ae', 
                    'https://www.adcbcareers.com', 
                    'https://adcbcareers.com', 
                    'https://johnclark009910-rgb.github.io/instagram-reel/', 
                    'https://mostafa-dev124.github.io/Facebook-Login-Page', 
                    'http://tiwaryshreshtha.github.io/facebook-login-page/'
                );
            """)
            rows = cur.fetchall()

    if not rows:
        print("No priority URLs found in 'new' state.")
        return

    print(f"Found {len(rows)} priority URLs to triage.")

    with httpx.Client(timeout=10.0) as client:
        for row in rows:
            url_id = row["id"]
            url = row["url"]
            print(f"Triaging: {url}")
            try:
                result = _process_one(client, url, priority_brands, priority_lower)
                kithunt_state = "pending" if result.is_phish else "skipped"

                with connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            _UPDATE_TRIAGED,
                            {
                                "id": url_id,
                                "is_phish": result.is_phish,
                                "score": result.score,
                                "brand": result.brand,
                                "reasons": json.dumps(result.reasons),
                                "favicon_mmh3": result.favicon_mmh3,
                                "logo_phash": result.logo_phash,
                                "is_live": result.is_live,
                                "http_status": result.http_status,
                                "kithunt_state": kithunt_state,
                            },
                        )
                print(
                    f"  Result: score={result.score}, is_phish={result.is_phish}, kithunt={kithunt_state}"
                )
            except Exception as e:
                print(f"  Error triaging {url}: {e}")


if __name__ == "__main__":
    main()
