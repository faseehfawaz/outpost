"""Headless-browser deep triage: render, screenshot, and watch the network.

The gap this closes
-------------------
Static triage fetches raw HTML with ``httpx`` and reads the DOM as served. A
large share of modern phishing kits are invisible to that:

* **SPA / JS-rendered kits.** The served HTML is an empty ``<div id="root">``
  and a bundle. ``analyze_forms`` finds no password field, ``detect_brand``
  finds no brand text, ``keyword_hits`` finds nothing. Score: 0. We discard a
  live credential harvester as uninteresting.
* **Image-only clones.** The login page is a single screenshot of the real bank
  with invisible inputs positioned over it. No brand *text* exists anywhere in
  the DOM.
* **Deferred exfil.** The endpoint that receives the credentials is assembled at
  runtime from string fragments, so it never appears in the source.

Rendering solves all three at once. We get the post-JavaScript DOM, a pixel
screenshot we can perceptually hash against the real brand login pages, and —
most valuable of all — the **observed network requests**, which reveal the
attacker's exfil endpoint directly.

Ethics
------
Unchanged from the rest of the platform, and enforced here explicitly:

* We render only what an anonymous visitor is served. No authentication, no
  interaction with the page, no form submission — :func:`render_page` never
  types into an input or clicks anything.
* **We never submit credentials, real or synthetic.** The exfil endpoint is
  learned by observing requests the page makes on load, not by baiting it.
* Downloads are disabled and JavaScript dialogs are auto-dismissed so a hostile
  page cannot wedge a worker.
* The per-host throttle is honoured before navigation, exactly as ``polite_get``
  would.

SATA-SSD note
-------------
Chromium is chatty on disk — profile, cache, code cache, GPU cache. Eight of
them on a SATA SSD would spend the day queued behind each other's writes, and
would age the drive for nothing. ``settings.render_tmpfs_dir`` defaults to
``/dev/shm``, so all of that lands in RAM instead. We have 32 GB; this costs
about 2-4 GB and removes the disk from the hot path entirely.
"""

from __future__ import annotations

import contextlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)

# Resource types we do not need and that cost the most time/bandwidth. Blocking
# them roughly halves render time without changing what the page *looks* like
# structurally. Images are kept — the screenshot is a primary signal.
_BLOCKED_RESOURCES = {"media", "font"}

# Request URL fragments that indicate credential exfiltration when a page issues
# them. Presence of a POST to an off-origin host is the strongest single signal
# the renderer can produce.
_EXFIL_HINTS = (
    "api.telegram.org",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "/send.php",
    "/post.php",
    "/save.php",
    "/log.php",
    "/submit.php",
    "formspree.io",
    "webhook.site",
)


@dataclass
class RenderResult:
    """Everything one headless render produced. All fields best-effort."""

    ok: bool = False
    final_url: str = ""
    status: int | None = None
    html: str | None = None
    title: str | None = None
    screenshot_path: str | None = None
    screenshot_phash: str | None = None
    # Off-origin endpoints the page contacted, and any that look like exfil.
    network_hosts: list[str] = field(default_factory=list)
    exfil_endpoints: list[str] = field(default_factory=list)
    has_password_field: bool = False
    input_count: int = 0
    error: str | None = None

    def signal_summary(self) -> dict:
        """Compact dict for the audit log / DB, safe to publish."""
        return {
            "rendered": self.ok,
            "title": self.title,
            "has_password_field": self.has_password_field,
            "input_count": self.input_count,
            "network_host_count": len(self.network_hosts),
            "exfil_endpoints": self.exfil_endpoints,
            "screenshot_phash": self.screenshot_phash,
        }


def playwright_available() -> bool:
    """True if Playwright is importable. The pipeline degrades without it."""
    try:
        import playwright.sync_api  # noqa: F401

        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
#  Thread-local Playwright instances
# ---------------------------------------------------------------------------
# Playwright's sync API uses greenlets that are bound to the creating thread.
# We cannot share a single Browser across the 64 triage worker threads.
# Instead, each thread in a dedicated render pool lazily creates its own
# Playwright → Browser pair via thread-local storage.  The pool size
# (render_browsers) caps how many Chromium processes exist simultaneously.
# ---------------------------------------------------------------------------

_tls = threading.local()


def _get_launch_kwargs() -> dict:
    """Build Chromium launch kwargs (no thread-local state)."""
    tmpfs = Path(settings.render_tmpfs_dir)
    tmpfs.mkdir(parents=True, exist_ok=True)
    crash_dir = tmpfs / "crashpad"
    crash_dir.mkdir(parents=True, exist_ok=True)

    launch_kwargs: dict = {
        "headless": True,
        "args": [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-background-networking",
            "--disable-extensions",
            "--disable-crash-reporter",
            "--enable-crashpad",
            f"--crash-dumps-dir={crash_dir}",
            # Keep cache in RAM, off the SATA SSD.
            f"--disk-cache-dir={tmpfs / 'cache'}",
            "--disk-cache-size=134217728",
        ],
        "env": {
            "CHROME_CRASHPAD_PIPE_NAME": "",
        },
    }
    exe = getattr(settings, "render_executable", "")
    if exe:
        launch_kwargs["executable_path"] = exe
    return launch_kwargs


def _ensure_thread_browser():
    """Return a Playwright Browser owned by the current thread, or None."""
    browser = getattr(_tls, "browser", None)
    if browser is not None:
        return browser

    try:
        from playwright.sync_api import sync_playwright

        pw = sync_playwright().start()
        browser = pw.chromium.launch(**_get_launch_kwargs())
        _tls.playwright = pw
        _tls.browser = browser
        log.info(
            "render_thread_browser_started",
            thread=threading.current_thread().name,
        )
        return browser
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "render_thread_browser_failed",
            thread=threading.current_thread().name,
            error=str(exc),
        )
        _tls.browser = None
        return None


class BrowserPool:
    """Fixed-size thread pool where each thread owns its own Playwright browser.

    Worker threads submit render jobs to this pool.  Because each pool thread
    lazily creates its own Playwright + Browser, there are no cross-thread
    greenlet issues.  The pool size (``settings.render_browsers``) limits
    how many concurrent Chromium processes run.
    """

    def __init__(self, size: int | None = None) -> None:
        self.size = size or settings.render_browsers
        self._executor = ThreadPoolExecutor(
            max_workers=self.size,
            thread_name_prefix="render",
        )

    def submit_render(self, url: str, *, save_screenshot: bool = True) -> RenderResult:
        """Submit a render job and block until complete."""
        future = self._executor.submit(_do_render, url, save_screenshot=save_screenshot)
        return future.result()

    @contextlib.contextmanager
    def context(self):
        """Yield an isolated browser context, or ``None`` if unavailable.

        DEPRECATED — kept for backward compatibility.  Prefer submit_render().
        The context is created on the *calling* thread, so it only works when
        the caller is already inside the render pool.
        """
        browser = _ensure_thread_browser()
        if browser is None:
            yield None
            return
        ctx = None
        try:
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=settings.user_agent,
                viewport={"width": 1366, "height": 900},
                accept_downloads=False,
                java_script_enabled=True,
            )
            ctx.set_default_timeout(settings.render_timeout_s * 1000)
            yield ctx
        except Exception as exc:  # noqa: BLE001
            log.warning("browser_context_failed", error=str(exc))
            yield None
        finally:
            if ctx is not None:
                with contextlib.suppress(Exception):
                    ctx.close()

    def close(self) -> None:
        self._executor.shutdown(wait=False)


_pool: BrowserPool | None = None
_pool_lock = threading.Lock()


def get_pool() -> BrowserPool:
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = BrowserPool()
    return _pool


def _screenshot_phash(png_bytes: bytes) -> str | None:
    """Perceptual hash of a screenshot.

    pHash (DCT-based) is chosen over average-hash because it tolerates the
    rescaling, recompression and minor colour shifts that a cloned login page
    picks up, while still separating genuinely different layouts.
    """
    try:
        import io

        import imagehash
        from PIL import Image

        img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
        return str(imagehash.phash(img, hash_size=16))
    except Exception as exc:  # noqa: BLE001
        log.debug("screenshot_phash_failed", error=str(exc))
        return None


def _do_render(url: str, *, save_screenshot: bool = True) -> RenderResult:
    """Execute the full render on a pool thread that owns a Playwright browser."""
    from pkintel.http import throttle_host

    result = RenderResult()
    origin_host = urlsplit(url).netloc.lower()
    throttle_host(origin_host)

    browser = _ensure_thread_browser()
    if browser is None:
        result.error = "browser_unavailable"
        return result

    ctx = None
    page = None
    try:
        ctx = browser.new_context(
            ignore_https_errors=True,
            user_agent=settings.user_agent,
            viewport={"width": 1366, "height": 900},
            accept_downloads=False,
            java_script_enabled=True,
        )
        ctx.set_default_timeout(settings.render_timeout_s * 1000)

        network_hosts: set[str] = set()
        exfil: list[str] = []

        def _on_request(request) -> None:
            try:
                host = urlsplit(request.url).netloc.lower()
                if host and host != origin_host:
                    network_hosts.add(host)
                lowered = request.url.lower()
                if request.method == "POST" and host and host != origin_host:
                    exfil.append(f"{request.method} {request.url}")
                elif any(hint in lowered for hint in _EXFIL_HINTS):
                    exfil.append(f"{request.method} {request.url}")
            except Exception:  # noqa: BLE001, S110
                pass

        def _on_route(route) -> None:
            try:
                if route.request.resource_type in _BLOCKED_RESOURCES:
                    route.abort()
                else:
                    route.continue_()
            except Exception:  # noqa: BLE001, S110
                with contextlib.suppress(Exception):
                    route.continue_()

        page = ctx.new_page()
        page.on("dialog", lambda d: d.dismiss())
        page.on("request", _on_request)
        page.route("**/*", _on_route)

        response = page.goto(url, wait_until="domcontentloaded")
        result.status = response.status if response else None

        with contextlib.suppress(Exception):
            page.wait_for_load_state("networkidle", timeout=8000)

        result.final_url = page.url
        result.title = (page.title() or "")[:300]
        result.html = page.content()

        result.has_password_field = bool(
            page.query_selector("input[type=password]")
        )
        result.input_count = len(page.query_selector_all("input"))

        if save_screenshot:
            png = page.screenshot(full_page=False, type="png")
            result.screenshot_phash = _screenshot_phash(png)
            shot_dir = Path(settings.render_screenshot_dir)
            try:
                shot_dir.mkdir(parents=True, exist_ok=True)
                from pkintel.redact import sha256_hex

                name = f"{sha256_hex(url)[:32]}.png"
                dest = shot_dir / name
                dest.write_bytes(png)
                result.screenshot_path = str(dest)
            except Exception as exc:  # noqa: BLE001 - hash is what matters
                log.debug("screenshot_save_failed", error=str(exc))

        result.network_hosts = sorted(network_hosts)
        result.exfil_endpoints = list(dict.fromkeys(exfil))[:20]
        result.ok = True

    except Exception as exc:  # noqa: BLE001 - a dead/hostile page is a normal outcome
        result.error = str(exc)[:500]
        log.debug("render_failed", url=url, error=result.error)
    finally:
        if page is not None:
            with contextlib.suppress(Exception):
                page.close()
        if ctx is not None:
            with contextlib.suppress(Exception):
                ctx.close()

    return result


def render_page(url: str, *, save_screenshot: bool = True) -> RenderResult:
    """Render ``url`` in a headless context and collect deep signals.

    Read-only: navigates, waits for the network to settle, then observes. It
    never interacts with the page and never submits anything.

    The actual work runs on a dedicated render-pool thread that owns its own
    Playwright browser, avoiding the greenlet thread-affinity crash.
    """
    result = RenderResult()
    if not settings.render_enabled:
        result.error = "render_disabled"
        return result

    pool = get_pool()
    return pool.submit_render(url, save_screenshot=save_screenshot)

