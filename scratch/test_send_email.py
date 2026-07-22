"""Test script to dispatch a sample takedown email to a test inbox.

Usage:
    python3 scratch/test_send_email.py --to faseehcodes@gmail.com
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pkintel.config import settings
from pkintel.takedown.mailer import send_takedown_email
from pkintel.takedown.templates import host_abuse_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Send test takedown email via SMTP")
    parser.add_argument("--to", default="faseehcodes@gmail.com", help="Destination test email")
    args = parser.parse_args()

    print(f"SMTP Host: {settings.smtp_host or '(Not set)'}")
    print(f"SMTP User: {settings.smtp_user or '(Not set)'}")
    print(f"Target:    {args.to}")

    # Generate sample report text
    mock_host_info = {
        "ip": "76.76.21.21",
        "asn": 13335,
        "asn_name": "CLOUDFLARENET",
        "registrar": "NameCheap Inc.",
    }
    subject, body = host_abuse_report(
        "https://facebook-login-page-kappa.vercel.app/login",
        mock_host_info,
        {"sha256": None, "count": 0},
    )

    print("\n--- SAMPLE EMAIL SUBJECT ---")
    print(subject)
    print("\n--- SAMPLE EMAIL BODY ---")
    print(body)
    print("---------------------------\n")

    if not settings.smtp_host:
        print("❌ Cannot send live email: PKINTEL_SMTP_HOST is not configured.")
        print("To send live emails to your inbox, set your SMTP credentials in your .env or environment:")
        print("  PKINTEL_SMTP_HOST=smtp.gmail.com")
        print("  PKINTEL_SMTP_PORT=587")
        print("  PKINTEL_SMTP_USER=your_gmail@gmail.com")
        print("  PKINTEL_SMTP_PASS=your_gmail_app_password")
        print("  PKINTEL_TAKEDOWN_FROM_EMAIL=your_gmail@gmail.com")
        return

    try:
        sent_to = send_takedown_email(args.to, f"[TEST] {subject}", body)
        print(f"✅ Email successfully sent to: {sent_to}")
    except Exception as err:
        print(f"❌ Failed to send email: {err}")


if __name__ == "__main__":
    main()
