"""Capture brand reference fingerprints automatically.

What this replaces
------------------
Two scoring signals depend on knowing what the *genuine* brand looks like:

* ``pkintel.triage.favicon.KNOWN_FAVICON_HASHES`` — a small hardcoded dict, used
  by the static scorer for ``favicon_known`` (+20) and ``favicon_brand_match``
  (+5).
* ``render_screenshot_dir/reference/<Brand>.phash`` — used by
  ``pkintel.triage.deep`` for ``screenshot_brand_match`` (+40), the signal that
  catches image-only clones carrying no brand text at all.

Both were operator homework: visit fourteen bank and government login pages and
record their fingerprints by hand. Worse, both fail **silently** when the data
is absent — the signals simply never fire, so nothing looks broken while two of
the strongest detectors sit switched off.

This module does that job automatically. Point it at the brand list and it
fetches each official login page once, computes the favicon hash and the
rendered screenshot pHash, and writes the reference set.

Is this ethical?
----------------
Yes, and it is worth being explicit. These are *our* targets' own public login
pages — Emirates NBD, ADCB, RTA and so on. We fetch each one exactly once,
through the same polite client and per-host throttle as everything else, and
read only what any visitor is served. This is the identical footprint of a
single person opening the page in a browser. We store a perceptual hash, not a
copy of the site.

Usage::

    pkintel refs capture              # capture every configured brand
    pkintel refs capture --brand ADCB # just one
    pkintel refs list                 # show what has been captured
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)

# Official login/homepage URLs for the priority brands.
#
# Chosen as the page an attacker would clone — the login form, not the marketing
# homepage — because that is what a phishing screenshot will resemble. Override
# or extend via a JSON file at <screenshot_dir>/reference/brands.json.
DEFAULT_BRAND_URLS: dict[str, str] = {
    "Emirates NBD": "https://www.emiratesnbd.com/en",
    "Emirates Islamic": "https://www.emiratesislamic.ae/en",
    "ADCB": "https://www.adcb.com/en",
    "FAB": "https://www.bankfab.com/en-ae",
    "Mashreq": "https://www.mashreqbank.com/uae/en/personal",
    "RTA": "https://www.rta.ae/wps/portal/rta/ae/home",
    "Etisalat": "https://www.etisalat.ae/en/index.jsp",
    "du": "https://www.du.ae/personal",
    "Dubai Police": "https://www.dubaipolice.gov.ae/wps/portal/home",
    "ADNOC": "https://www.adnoc.ae/en",
    "DEWA": "https://www.dewa.gov.ae/en",
    "Emirates": "https://www.emirates.com/ae/english/",
    "Emirates Post": "https://emiratespost.ae/en",
    "UAE PASS": "https://uaepass.ae/",
}


@dataclass
class BrandReference:
    """Captured fingerprints for one brand."""

    brand: str
    url: str
    favicon_mmh3: int | None = None
    favicon_phash: str | None = None
    screenshot_phash: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.favicon_mmh3 is not None or self.screenshot_phash is not None


def reference_dir() -> Path:
    return Path(settings.render_screenshot_dir) / "reference"


def load_brand_urls() -> dict[str, str]:
    """Brand -> official URL, with an optional operator override file."""
    override = reference_dir() / "brands.json"
    urls = dict(DEFAULT_BRAND_URLS)
    if override.is_file():
        try:
            urls.update(json.loads(override.read_text()))
            log.info("brand_urls_override_loaded", path=str(override))
        except Exception as exc:  # noqa: BLE001
            log.warning("brand_urls_override_failed", error=str(exc))
    return urls


def _capture_static(brand: str, url: str, ref: BrandReference) -> None:
    """Fetch the favicon via the polite HTTP client."""
    from pkintel.http import polite_client
    from pkintel.triage.favicon import favicon_mmh3
    from pkintel.triage.fetch import fetch_page
    from pkintel.triage.phash import logo_phash

    client = polite_client()
    try:
        fetched = fetch_page(client, url)
        if fetched.error:
            ref.errors.append(f"fetch: {fetched.error}")
            return
        if not fetched.favicon_bytes:
            ref.errors.append("no favicon served")
            return
        ref.favicon_mmh3 = favicon_mmh3(fetched.favicon_bytes)
        ref.favicon_phash = logo_phash(fetched.favicon_bytes)
    finally:
        client.close()


def _capture_rendered(brand: str, url: str, ref: BrandReference) -> None:
    """Render the page and hash the screenshot."""
    from pkintel.triage.render import render_page

    result = render_page(url, save_screenshot=True)
    if not result.ok:
        ref.errors.append(f"render: {result.error}")
        return
    if not result.screenshot_phash:
        ref.errors.append("render produced no screenshot hash")
        return
    ref.screenshot_phash = result.screenshot_phash


def capture_brand(brand: str, url: str, *, render: bool = True) -> BrandReference:
    """Capture one brand's reference fingerprints. Never raises."""
    ref = BrandReference(brand=brand, url=url)

    try:
        _capture_static(brand, url, ref)
    except Exception as exc:  # noqa: BLE001
        ref.errors.append(f"static: {exc}")

    if render:
        try:
            _capture_rendered(brand, url, ref)
        except Exception as exc:  # noqa: BLE001
            ref.errors.append(f"render: {exc}")

    log.info(
        "brand_reference_captured",
        brand=brand,
        favicon_mmh3=ref.favicon_mmh3,
        screenshot_phash=ref.screenshot_phash,
        errors=ref.errors or None,
    )
    return ref


def write_references(refs: list[BrandReference]) -> Path:
    """Persist references to disk in the layouts the scorers expect.

    Writes three things:
      * ``<Brand>.phash``    — read by ``pkintel.triage.deep._load_brand_references``
      * ``favicons.json``    — read by ``pkintel.triage.favicon`` at import
      * ``references.json``  — full record, for auditing what was captured when
    """
    out_dir = reference_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    for ref in refs:
        if ref.screenshot_phash:
            # Filename is the brand, since deep.py uses path.stem as the label.
            (out_dir / f"{ref.brand}.phash").write_text(ref.screenshot_phash)

    favicons = {str(r.favicon_mmh3): r.brand for r in refs if r.favicon_mmh3 is not None}
    (out_dir / "favicons.json").write_text(json.dumps(favicons, indent=2, sort_keys=True))

    (out_dir / "references.json").write_text(
        json.dumps(
            [
                {
                    "brand": r.brand,
                    "url": r.url,
                    "favicon_mmh3": r.favicon_mmh3,
                    "favicon_phash": r.favicon_phash,
                    "screenshot_phash": r.screenshot_phash,
                    "errors": r.errors,
                }
                for r in refs
            ],
            indent=2,
        )
    )
    return out_dir


def capture_all(brands: list[str] | None = None, *, render: bool = True) -> list[BrandReference]:
    """Capture every configured brand (or a subset). Returns the references."""
    urls = load_brand_urls()
    if brands:
        wanted = {b.strip().lower() for b in brands}
        urls = {k: v for k, v in urls.items() if k.lower() in wanted}
        if not urls:
            log.warning("no_matching_brands", requested=brands, known=sorted(load_brand_urls()))
            return []

    refs: list[BrandReference] = []
    for brand, url in urls.items():
        refs.append(capture_brand(brand, url, render=render))

    write_references(refs)
    return refs
