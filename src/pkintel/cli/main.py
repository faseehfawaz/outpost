"""``pkintel`` command-line interface.

The single operator entrypoint. Ties the independent subsystem runners together
behind a uniform ``run`` command and provides DB lifecycle helpers.

    pkintel db migrate
    pkintel db seed
    pkintel run ingest --once
    pkintel run all --loop --interval 30

Every stage's runner obeys the same contract: ``run_once(worker_id, limit) -> int``
(number of items processed). Runners are imported lazily so a problem in one
subsystem never breaks the whole CLI and importing the CLI never touches the DB.
"""

from __future__ import annotations

import importlib
import time
from collections.abc import Callable

import typer

from pkintel.logging import configure_logging, get_logger

app = typer.Typer(add_completion=False, help="pkintel — phishing-kit intelligence pipeline")
db_app = typer.Typer(help="Database lifecycle")
run_app = typer.Typer(help="Run pipeline stages")
refs_app = typer.Typer(help="Brand reference fingerprints")
app.add_typer(db_app, name="db")
app.add_typer(run_app, name="run")
app.add_typer(refs_app, name="refs")

log = get_logger(__name__)

# stage name -> (dotted runner module, default batch limit)
#
# Batch limits were sized for the old one-URL-at-a-time runners. With the
# concurrent pools (see pkintel.pool) a batch is drained in roughly
# batch/workers round-trips, so small batches now just mean the pool spends its
# time idle between claims. They are raised to keep the pool saturated.
STAGES: dict[str, tuple[str, int]] = {
    "ingest": ("pkintel.ingest.runner", 2000),
    "triage": ("pkintel.triage.runner", 500),  # was 50
    "kithunt": ("pkintel.kithunter.runner", 60),  # was 10
    "analyze": ("pkintel.analyzer.runner", 30),  # was 5
    "cluster": ("pkintel.fingerprint.runner", 0),  # global op; limit ignored
    "enrich": ("pkintel.enrich.runner", 200),
    "pivot": ("pkintel.fingerprint.pivot", 0),  # global op; limit ignored
    "takedown": ("pkintel.takedown.runner", 100),  # was 20
    "verify": ("pkintel.takedown.verify", 100),
}

# Canonical execution order for `all`.
#
# `enrich` MUST run before `pivot`: it is what populates hosts.ip /
# .cert_sha256 / .asn, and the pivot's two strongest edges (shared_cert 1.0,
# shared_ip 0.7) read exactly those columns. Run the other way round and the
# pivot silently clusters on nothing.
#
# `pivot` then runs before `takedown`, so a campaign sibling discovered this
# cycle can be reported in the same cycle that found it.
#
# `verify` runs last: it only ever touches takedowns already marked sent, so it
# has no effect on anything downstream in the same cycle.
PIPELINE_ORDER = [
    "ingest",
    "triage",
    "kithunt",
    "analyze",
    "cluster",
    "enrich",
    "pivot",
    "takedown",
    "verify",
]


def _load_runner(stage: str) -> Callable[..., int]:
    module_path, _ = STAGES[stage]
    module = importlib.import_module(module_path)
    fn = getattr(module, "run_once", None)
    if fn is None:
        raise typer.BadParameter(f"{module_path} does not expose run_once()")
    return fn


def _run_stage_once(stage: str, worker_id: str | None = None) -> int:
    _, limit = STAGES[stage]
    runner = _load_runner(stage)
    wid = worker_id or f"{stage}-cli"

    started = time.monotonic()
    processed = runner(worker_id=wid, limit=limit)
    elapsed = time.monotonic() - started

    # Every stage gets a duration histogram for free here, so individual runners
    # only need to record metrics that are specific to them.
    try:
        from pkintel.metrics import stage_duration

        stage_duration.labels(stage=stage).observe(elapsed)
    except Exception:  # noqa: BLE001, S110
        pass

    log.info("stage_done", stage=stage, processed=processed, elapsed_s=round(elapsed, 2))
    return processed


# --------------------------------------------------------------------------- db
@db_app.command("migrate")
def db_migrate() -> None:
    """Apply all pending SQL migrations."""
    configure_logging()
    from pkintel.db import run_migrations

    applied = run_migrations()
    if applied:
        typer.echo(f"Applied: {', '.join(applied)}")
    else:
        typer.echo("Already up to date.")


@db_app.command("seed")
def db_seed() -> None:
    """Register the feed sources."""
    configure_logging()
    from pkintel.cli.seed import seed_sources

    n = seed_sources()
    typer.echo(f"Seeded {n} sources.")


@db_app.command("ping")
def db_ping() -> None:
    """Check database connectivity."""
    configure_logging()
    from pkintel.db import fetch_one

    row = fetch_one("SELECT 1 AS ok")
    typer.echo("ok" if row and row.get("ok") == 1 else "unreachable")


@db_app.command("reap")
def db_reap() -> None:
    """Recover rows abandoned by dead workers.

    A worker killed mid-batch (OOM, SIGKILL, power cut, systemctl restart) left
    its rows pinned in a busy state forever, with nothing to release them. Run
    this on a timer — `pkintel run reaper --loop` does exactly that.
    """
    configure_logging()
    from pkintel.db import reap_stuck_rows

    recovered = reap_stuck_rows()
    if recovered:
        for queue, n in recovered.items():
            typer.echo(f"recovered {n} stuck rows in {queue}")
    else:
        typer.echo("no stuck rows.")


@db_app.command("queues")
def db_queues() -> None:
    """Print current depth of every work queue."""
    configure_logging()
    from pkintel.db import queue_depths

    for queue, n in sorted(queue_depths().items()):
        typer.echo(f"{queue:20s} {n:>8d}")


# -------------------------------------------------------------------------- run
@run_app.command("ingest")
def run_ingest(once: bool = True, loop: bool = False, interval: int = 30) -> None:
    _run("ingest", once, loop, interval)


@run_app.command("triage")
def run_triage(once: bool = True, loop: bool = False, interval: int = 30) -> None:
    _run("triage", once, loop, interval)


@run_app.command("kithunt")
def run_kithunt(once: bool = True, loop: bool = False, interval: int = 30) -> None:
    _run("kithunt", once, loop, interval)


@run_app.command("analyze")
def run_analyze(once: bool = True, loop: bool = False, interval: int = 30) -> None:
    _run("analyze", once, loop, interval)


@run_app.command("cluster")
def run_cluster(once: bool = True, loop: bool = False, interval: int = 60) -> None:
    _run("cluster", once, loop, interval)


@run_app.command("takedown")
def run_takedown(once: bool = True, loop: bool = False, interval: int = 60) -> None:
    _run("takedown", once, loop, interval)


@run_app.command("enrich")
def run_enrich(once: bool = True, loop: bool = False, interval: int = 120) -> None:
    """Resolve phish hosts, map their ASN, and fingerprint their TLS cert."""
    _run("enrich", once, loop, interval)


@run_app.command("pivot")
def run_pivot(once: bool = True, loop: bool = False, interval: int = 300) -> None:
    """Rebuild the infrastructure pivot graph (shared IP/cert/favicon/exfil).

    Run AFTER `enrich` — it reads the columns enrich populates.
    """
    _run("pivot", once, loop, interval)


@run_app.command("verify")
def run_verify(once: bool = True, loop: bool = False, interval: int = 900) -> None:
    """Re-probe sent takedowns, confirm deaths, and escalate the stubborn ones."""
    _run("verify", once, loop, interval)


@run_app.command("certstream")
def run_certstream() -> None:
    """Consume the Certificate Transparency firehose (long-lived, push-based).

    Does not take --loop/--interval: it is a websocket stream, not a batch, so
    it does not fit the run_once contract. It reconnects with exponential
    backoff on its own. Run it as outpost-certstream.service.
    """
    configure_logging()
    from pkintel.ingest.certstream import main as certstream_main

    certstream_main()


@run_app.command("reaper")
def run_reaper(once: bool = True, loop: bool = False, interval: int = 300) -> None:
    """Continuously recover rows abandoned by dead workers.

    Runs as its own service (outpost-reaper.service). Cheap — the partial
    indexes from migration 003 make each pass O(stuck), not O(table).
    """
    configure_logging()
    from pkintel.db import reap_stuck_rows

    if loop:
        log.info("reaper_loop_start", interval=interval)
        while True:
            reap_stuck_rows()
            time.sleep(interval)
    else:
        recovered = reap_stuck_rows()
        typer.echo(f"recovered: {recovered or 'nothing'}")


@run_app.command("all")
def run_all(once: bool = True, loop: bool = False, interval: int = 30) -> None:
    """Run every stage in pipeline order.

    NOTE: this runs the stages *sequentially* in one process, so a slow stage
    blocks every stage behind it. It stays for dev and one-shot runs. In
    production use the per-stage systemd units (deploy/outpost-*.service), which
    run the stages as independent, concurrently-scheduled services so ingest
    never blocks triage.
    """
    configure_logging()

    def one_pass() -> int:
        total = 0
        for stage in PIPELINE_ORDER:
            try:
                total += _run_stage_once(stage)
            except Exception as exc:  # keep the pipeline moving; log and continue
                log.error("stage_failed", stage=stage, error=str(exc))
        return total

    if loop:
        log.info("pipeline_loop_start", interval=interval)
        while True:
            one_pass()
            time.sleep(interval)
    else:
        typer.echo(f"Processed {one_pass()} items across the pipeline.")


# ------------------------------------------------------------------------- refs
@refs_app.command("capture")
def refs_capture(
    brand: list[str] = typer.Option(None, "--brand", "-b", help="Only these brands"),
    no_render: bool = typer.Option(False, "--no-render", help="Favicon only, skip screenshots"),
) -> None:
    """Capture brand reference fingerprints (favicon hash + screenshot pHash).

    Activates two scoring signals that are otherwise silently switched off:
    favicon_known (+20) and screenshot_brand_match (+40). Fetches each official
    login page exactly once through the polite client.
    """
    configure_logging()
    from pkintel.tools.references import capture_all, reference_dir

    refs = capture_all(brands=list(brand) if brand else None, render=not no_render)
    if not refs:
        typer.echo("No brands captured.")
        raise typer.Exit(code=1)

    ok = [r for r in refs if r.usable]
    for r in refs:
        mark = "ok " if r.usable else "FAIL"
        bits = []
        if r.favicon_mmh3 is not None:
            bits.append(f"favicon={r.favicon_mmh3}")
        if r.screenshot_phash:
            bits.append("screenshot=yes")
        if r.errors:
            bits.append(f"errors={'; '.join(r.errors)}")
        typer.echo(f"  [{mark}] {r.brand:20s} {' '.join(bits)}")

    typer.echo(f"\n{len(ok)}/{len(refs)} brands captured -> {reference_dir()}")


@refs_app.command("list")
def refs_list() -> None:
    """Show which brand references have been captured."""
    configure_logging()
    import json

    from pkintel.tools.references import load_brand_urls, reference_dir

    path = reference_dir() / "references.json"
    if not path.is_file():
        typer.echo("No references captured yet. Run: pkintel refs capture")
        raise typer.Exit(code=1)

    data = json.loads(path.read_text())
    known = load_brand_urls()
    for entry in data:
        fav = entry.get("favicon_mmh3")
        shot = "yes" if entry.get("screenshot_phash") else "no"
        typer.echo(f"  {entry['brand']:20s} favicon={fav!s:14s} screenshot={shot}")
    captured = {e["brand"] for e in data}
    missing = sorted(set(known) - captured)
    if missing:
        typer.echo(f"\nNot yet captured: {', '.join(missing)}")


def _run(stage: str, once: bool, loop: bool, interval: int) -> None:
    configure_logging()
    if loop:
        log.info("stage_loop_start", stage=stage, interval=interval)
        while True:
            _run_stage_once(stage)
            time.sleep(interval)
    else:
        n = _run_stage_once(stage)
        typer.echo(f"{stage}: processed {n} items.")


if __name__ == "__main__":
    app()
