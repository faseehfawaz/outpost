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
app.add_typer(db_app, name="db")
app.add_typer(run_app, name="run")

log = get_logger(__name__)

# stage name -> (dotted runner module, default batch limit)
STAGES: dict[str, tuple[str, int]] = {
    "ingest": ("pkintel.ingest.runner", 500),
    "triage": ("pkintel.triage.runner", 50),
    "kithunt": ("pkintel.kithunter.runner", 10),
    "analyze": ("pkintel.analyzer.runner", 5),
    "cluster": ("pkintel.fingerprint.runner", 0),
    "takedown": ("pkintel.takedown.runner", 20),
}

# canonical execution order for `all`
PIPELINE_ORDER = ["ingest", "triage", "kithunt", "analyze", "cluster", "takedown"]


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
    processed = runner(worker_id=wid, limit=limit)
    log.info("stage_done", stage=stage, processed=processed)
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


@run_app.command("all")
def run_all(once: bool = True, loop: bool = False, interval: int = 30) -> None:
    """Run every stage in pipeline order."""
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
