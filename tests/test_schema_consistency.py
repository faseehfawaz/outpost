"""Static check: every SQL query in the codebase matches the actual schema.

Why this test exists
--------------------
The single worst bug found in this codebase was in ``takedown/runner.py``::

    SELECT value FROM indicators WHERE kit_id = %s AND type = 'telegram'

The ``indicators`` table has no ``value`` column, and ``IndicatorType`` has no
``telegram`` member. The query was inside a broad ``try/except`` that logged and
moved on, so it failed silently on every run. **Telegram takedowns never fired
once**, and nothing in the logs said so.

Unit tests could not catch it: the query only executes with a live database, and
the exception was swallowed. Integration tests would catch it, but only if
someone had a kit with Telegram indicators to trigger that branch.

This test catches that entire class of bug with no database at all. It builds
the real schema by parsing ``db/migrations/*.sql``, extracts every SQL string
from the source, and verifies that every table and column referenced actually
exists.

It is deliberately conservative — it reports a failure only when it is confident
a reference is wrong, because a noisy schema test gets disabled and then protects
nothing.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

# Hard import, deliberately NOT pytest.importorskip.
#
# This used to be `importorskip("sqlglot")` while sqlglot was declared in
# neither pyproject.toml nor uv.lock — so the whole module skipped in every
# local run and every CI job, silently, and the suite reported "295 passed,
# 1 skipped" while covering none of this. A query referencing a non-existent
# `indicators.created_at` column then shipped and 500'd the public IOC feed:
# exactly the class of bug this file was written to catch, described in its own
# docstring above.
#
# sqlglot is now a declared dev dependency. If it is missing the suite should
# FAIL loudly, because the alternative is a guard that quietly guards nothing.
import sqlglot  # noqa: E402, F401
from sqlglot import exp  # noqa: E402

_ = pytest  # re-exported below for the fixtures

REPO = Path(__file__).resolve().parents[1]
MIGRATIONS = REPO / "db" / "migrations"
SRC = REPO / "src" / "pkintel"

# Columns Postgres provides implicitly, plus our parameter placeholders.
_SYSTEM_COLUMNS = {"xmax", "xmin", "ctid", "tableoid", "oid", "now", "id"}

# Identifiers that appear in SQL but are aliases/CTEs/functions, not real columns.
_NOT_COLUMNS = {"claimed", "excluded", "count", "q", "n", "ok"}


def _strip_sql_comments(sql: str) -> str:
    """Remove ``--`` line comments and ``/* */`` block comments, preserving strings.

    This must happen BEFORE splitting on semicolons. Our migrations are heavily
    commented and those comments contain both apostrophes (``attacker's``) and
    semicolons (``payloads go in JSONB; everything else is typed``). A splitter
    that tracks quote state without skipping comments treats a comment
    apostrophe as opening a string literal, desynchronises, and silently drops
    every statement after it — which is exactly what happened here: four tables
    and five columns vanished from the parsed schema with no error raised.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    in_string = False
    while i < n:
        ch = sql[i]
        if in_string:
            out.append(ch)
            if ch == "'":
                if i + 1 < n and sql[i + 1] == "'":  # escaped quote
                    out.append("'")
                    i += 2
                    continue
                in_string = False
            i += 1
            continue

        if ch == "'":
            in_string = True
            out.append(ch)
            i += 1
        elif ch == "-" and i + 1 < n and sql[i + 1] == "-":
            while i < n and sql[i] != "\n":
                i += 1
        elif ch == "/" and i + 1 < n and sql[i + 1] == "*":
            i += 2
            while i + 1 < n and not (sql[i] == "*" and sql[i + 1] == "/"):
                i += 1
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _split_statements(sql: str) -> list[str]:
    """Split a migration into statements on semicolons outside string literals."""
    sql = _strip_sql_comments(sql)
    out: list[str] = []
    buf: list[str] = []
    in_string = False
    i = 0
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            # '' inside a string is an escaped quote, not a terminator.
            if in_string and i + 1 < len(sql) and sql[i + 1] == "'":
                buf.append("''")
                i += 2
                continue
            in_string = not in_string
            buf.append(ch)
        elif ch == ";" and not in_string:
            stmt = "".join(buf).strip()
            if stmt:
                out.append(stmt)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def build_schema() -> dict[str, set[str]]:
    """Parse every migration in order into ``{table: {columns}}``.

    Applies CREATE TABLE and ALTER TABLE ... ADD COLUMN in filename order, which
    is exactly the order ``pkintel.db.run_migrations`` applies them.
    """
    schema: dict[str, set[str]] = {}

    for path in sorted(MIGRATIONS.glob("*.sql")):
        sql = path.read_text()
        # Parse statement-by-statement. Migrations legitimately contain DDL that
        # sqlglot cannot model (CREATE EXTENSION, COMMENT ON, partial-index
        # predicates); those carry no column definitions, so skipping them loses
        # nothing while letting the rest of the file be checked.
        for chunk in _split_statements(sql):
            try:
                statement = sqlglot.parse_one(chunk, dialect="postgres")
            except Exception:  # noqa: BLE001
                continue
            if statement is None:
                continue

            # CREATE TABLE
            if isinstance(statement, exp.Create) and statement.kind == "TABLE":
                table = statement.find(exp.Table)
                if table is None:
                    continue
                name = table.name.lower()
                cols = schema.setdefault(name, set())
                for coldef in statement.find_all(exp.ColumnDef):
                    cols.add(coldef.name.lower())

            # ALTER TABLE ... ADD COLUMN
            elif isinstance(statement, exp.Alter):
                table = statement.find(exp.Table)
                if table is None:
                    continue
                name = table.name.lower()
                cols = schema.setdefault(name, set())
                for coldef in statement.find_all(exp.ColumnDef):
                    cols.add(coldef.name.lower())

    return schema


def _normalise_placeholders(sql: str) -> str:
    """Replace psycopg placeholders with ``NULL`` so the SQL parses.

    ``NULL`` rather than ``?`` on purpose: several queries cast a placeholder
    (``%s::jsonb``, ``%s::text``), and ``?::jsonb`` is not valid SQL while
    ``NULL::jsonb`` is. Using ``?`` produced parse errors that looked like code
    bugs but were artifacts of this substitution.
    """
    sql = re.sub(r"%\([A-Za-z_][A-Za-z0-9_]*\)s", "NULL", sql)
    return sql.replace("%s", "NULL")


def extract_sql_strings() -> list[tuple[Path, int, str]]:
    """Pull every string literal that looks like SQL out of the Python source.

    Returns ``(file, lineno, sql)``. Placeholders are normalised so sqlglot can
    parse them: psycopg's ``%s`` / ``%(name)s`` are not valid SQL.
    """
    out: list[tuple[Path, int, str]] = []
    # Require a *keyword pair*, not just a leading verb. Matching on the verb
    # alone swept up ordinary English from the phishing-keyword list —
    # "update your account", "verify your identity" — and then reported `your`
    # as an unknown table. A real statement always pairs its verb with a clause.
    sql_start = re.compile(
        r"(SELECT\b[\s\S]+?\bFROM\b"
        r"|INSERT\s+INTO\b"
        r"|UPDATE\b[\s\S]+?\bSET\b"
        r"|DELETE\s+FROM\b"
        r"|WITH\b[\s\S]+?\bAS\s*\()",
        re.IGNORECASE,
    )

    for py in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(py.read_text())
        except SyntaxError:  # pragma: no cover
            continue

        # Docstrings routinely *describe* SQL — pkintel.db's own module docstring
        # says "Workers claim rows with ``SELECT ... FOR UPDATE SKIP LOCKED``".
        # That is prose, not a query, and parsing it produces noise.
        skip: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = getattr(node, "body", None)
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    skip.add(id(body[0].value))
            # Fragments of an f-string are individually meaningless SQL. The
            # only f-string SQL we build is claim_rows(), covered separately by
            # test_claim_rows_targets_real_tables.
            if isinstance(node, ast.JoinedStr):
                for part in ast.walk(node):
                    if isinstance(part, ast.Constant):
                        skip.add(id(part))

        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in skip:
                continue
            raw = node.value
            if not sql_start.search(raw):
                continue
            if "{" in raw and "}" in raw:
                continue
            out.append((py, node.lineno, _normalise_placeholders(raw)))
    return out


@pytest.fixture(scope="module")
def schema() -> dict[str, set[str]]:
    s = build_schema()
    assert s, "no schema parsed from db/migrations — check the path"
    # Created at runtime by pkintel.db.run_migrations, not by a migration file.
    s.setdefault("schema_migrations", set()).update({"filename", "applied_at"})
    return s


# --------------------------------------------------------------------------- schema sanity
def test_expected_tables_exist(schema):
    """The migrations must define the tables the code depends on."""
    for table in [
        "urls",
        "hosts",
        "kits",
        "kit_files",
        "indicators",
        "fingerprints",
        "actors",
        "takedowns",
        "audit_log",
        "sources",
        "host_edges",
    ]:
        assert table in schema, f"table `{table}` missing from migrations"


def test_migration_003_and_004_columns_applied(schema):
    """Columns added by the new migrations must be visible to the checker."""
    assert "priority" in schema["urls"], "003 did not add urls.priority"
    assert "reap_count" in schema["urls"], "003 did not add urls.reap_count"
    assert "screenshot_phash" in schema["urls"]
    assert "cloaking_score" in schema["urls"]
    assert "exfil_endpoints" in schema["urls"]
    assert "rendered" in schema["urls"]

    assert "target_dead_at" in schema["takedowns"], "003 did not add takedowns.target_dead_at"
    assert "escalation_level" in schema["takedowns"]
    assert "verify_after" in schema["takedowns"]

    assert "enrich_state" in schema["hosts"], "004 did not add hosts.enrich_state"
    assert "cert_sha256" in schema["hosts"]
    assert "ips" in schema["hosts"]
    assert "nameservers" in schema["hosts"]


def test_reaper_tables_all_have_lock_columns(schema):
    """reap_stuck_rows() writes locked_by/locked_at/<counter> on each table.

    The counter column is per-entry rather than always ``reap_count``: `urls`
    runs two independent state machines (triage and kithunt) over the same row,
    and sharing one counter let a flaky stage poison rows on behalf of a stage
    that was fine.
    """
    from pkintel.db import _REAPABLE

    for table, state_col, _busy, _ready, _lease, count_col in _REAPABLE:
        assert table in schema, f"reaper targets unknown table `{table}`"
        for required in ("locked_by", "locked_at", count_col, state_col):
            assert required in schema[table], (
                f"reaper needs {table}.{required} but the migrations do not define it"
            )


def test_queue_depths_columns_exist(schema):
    """queue_depths() is on the /health endpoint; a bad column would 500 it."""
    assert "triage_state" in schema["urls"]
    assert "kithunt_state" in schema["urls"]
    assert "analysis_state" in schema["kits"]
    assert "status" in schema["takedowns"]
    assert "enrich_state" in schema["hosts"]


# --------------------------------------------------------------------------- the real check
def _referenced_tables(tree) -> set[str]:
    return {t.name.lower() for t in tree.find_all(exp.Table) if t.name}


def test_every_query_references_only_real_tables(schema):
    """No query may reference a table the migrations never create."""
    problems: list[str] = []
    known = set(schema) | {"schema_migrations"}

    for path, lineno, sql in extract_sql_strings():
        try:
            tree = sqlglot.parse_one(sql, dialect="postgres")
        except Exception:  # noqa: BLE001 - unparseable is covered by the next test
            continue
        if tree is None:
            continue
        for table in _referenced_tables(tree):
            # CTE names look like tables to the parser.
            cte_names = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
            if table in known or table in cte_names or table in _NOT_COLUMNS:
                continue
            problems.append(f"{path.relative_to(REPO)}:{lineno} unknown table `{table}`")

    assert not problems, "queries reference tables that do not exist:\n" + "\n".join(problems)


def test_every_column_reference_exists_somewhere(schema):
    """Every column named in a query must exist on some table in the schema.

    Deliberately checks membership in the *union* of all columns rather than
    resolving each column to its specific table. Full resolution needs alias
    tracking across joins and subqueries, and getting that subtly wrong would
    produce false failures — which is how schema tests end up disabled.

    The union check is still strong enough to catch the real bug class: a
    column name that exists nowhere in the database is always wrong. That is
    exactly what `SELECT value FROM indicators` was.
    """
    all_columns: set[str] = set()
    for cols in schema.values():
        all_columns |= cols
    all_columns |= _SYSTEM_COLUMNS | _NOT_COLUMNS

    problems: list[str] = []
    for path, lineno, sql in extract_sql_strings():
        try:
            tree = sqlglot.parse_one(sql, dialect="postgres")
        except Exception:  # noqa: BLE001
            continue
        if tree is None:
            continue

        aliases = {a.alias_or_name.lower() for a in tree.find_all(exp.Alias)}

        for col in tree.find_all(exp.Column):
            name = col.name.lower()
            if not name or name in all_columns or name in aliases:
                continue
            problems.append(f"{path.relative_to(REPO)}:{lineno} column `{name}` exists on no table")

    assert not problems, (
        "queries reference columns that exist nowhere in the schema:\n"
        + "\n".join(sorted(set(problems)))
    )


def test_all_sql_parses_as_postgres():
    """Every SQL literal must be syntactically valid Postgres."""
    problems: list[str] = []
    for path, lineno, sql in extract_sql_strings():
        try:
            sqlglot.parse_one(sql, dialect="postgres")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path.relative_to(REPO)}:{lineno} {type(exc).__name__}: {exc}")
    assert not problems, "unparseable SQL:\n" + "\n".join(problems)


def test_migrations_have_balanced_transactions():
    """Every migration must open and close exactly one transaction.

    A migration that BEGINs without COMMITting leaves ``run_migrations`` holding
    an open transaction, and the next migration's DDL then blocks behind it.
    """
    for path in sorted(MIGRATIONS.glob("*.sql")):
        text = path.read_text().upper()
        begins = len(re.findall(r"^\s*BEGIN\s*;", text, re.MULTILINE))
        commits = len(re.findall(r"^\s*COMMIT\s*;", text, re.MULTILINE))
        assert begins == commits, (
            f"{path.name}: {begins} BEGIN vs {commits} COMMIT — unbalanced transaction"
        )


def test_new_migrations_are_idempotent():
    """003/004 must be safely re-runnable — they may hit a partly-migrated DB.

    ``run_migrations`` tracks applied files, but an operator re-running a
    migration by hand (or a crash between the DDL and the tracking INSERT) must
    not leave the schema wedged.
    """
    for name in ("003_priority_reaper_pivot.sql", "004_host_enrichment.sql"):
        path = MIGRATIONS / name
        if not path.exists():
            continue
        sql = path.read_text()
        for stmt in _split_statements(sql):
            head = stmt.strip().upper()
            if head.startswith("ALTER TABLE") and "ADD COLUMN" in head:
                assert "IF NOT EXISTS" in head, f"{name}: non-idempotent ADD COLUMN:\n{stmt[:120]}"
            if head.startswith("CREATE INDEX") or head.startswith("CREATE UNIQUE INDEX"):
                assert "IF NOT EXISTS" in head, (
                    f"{name}: non-idempotent CREATE INDEX:\n{stmt[:120]}"
                )
            if head.startswith("CREATE TABLE"):
                assert "IF NOT EXISTS" in head, (
                    f"{name}: non-idempotent CREATE TABLE:\n{stmt[:120]}"
                )


def test_the_original_telegram_bug_would_be_caught(schema):
    """Regression guard for the exact bug this test was written to prevent."""
    assert "value" not in schema["indicators"], (
        "indicators.value now exists — if that was intentional, this guard can go"
    )
    assert "value_hash" in schema["indicators"]
    assert "redacted_display" in schema["indicators"]
    assert "full_value_encrypted" in schema["indicators"]


def test_indicator_type_values_match_what_queries_filter_on():
    """The takedown query filters on indicator types; they must be real enum members."""
    from pkintel.models import IndicatorType

    members = {m.value for m in IndicatorType}
    # These are the literals used in takedown/runner.py after the fix.
    for used in ("telegram_token", "telegram_chat", "discord_webhook", "email"):
        assert used in members, f"query filters on type '{used}' which is not an IndicatorType"
    # The original bug filtered on a type that never existed.
    assert "telegram" not in members
