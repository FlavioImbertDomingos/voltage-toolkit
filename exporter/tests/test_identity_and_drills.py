"""R10a identity activity and R11 restore drills: pure evaluation, source plumbing, metrics."""

from __future__ import annotations

import csv
import os
import sqlite3
import subprocess
import sys

import pytest
from prometheus_client import REGISTRY

from voltage_exporter import identity_activity as ia
from voltage_exporter import metrics
from voltage_exporter import restore_drills as rd
from voltage_exporter.sources import SourceError

H = 3600.0
NOW = 1_800_000_000.0


def _cfg(**over):
    base = {
        "source": {"type": "file", "path": "/dev/null"},
        "window": "1h",
        "baseline_windows": 4,
        "spike_ratio": 5,
        "min_events": 10,
        "declared_identities": ["app@x", "batch@x"],
    }
    base.update(over)
    return ia.parse_config(base)


def _rows(spec):
    """spec: list of (hours_ago, identity, event, n)."""
    out = []
    for hours_ago, ident, event, n in spec:
        for i in range(n):
            out.append((NOW - hours_ago * H - i * 0.5, ident, event))
    return out


def test_identity_baseline_spike_new_and_undeclared():
    rows = _rows(
        [(4.5, "app@x", "key_request", 10), (3.5, "app@x", "key_request", 12), (2.5, "app@x", "key_request", 9),
         (1.5, "app@x", "key_request", 11), (0.5, "app@x", "key_request", 10),  # steady: ratio ~1
         (4.5, "batch@x", "key_request", 5), (3.5, "batch@x", "key_request", 5), (2.5, "batch@x", "key_request", 5),
         (1.5, "batch@x", "key_request", 5), (0.5, "batch@x", "key_request", 200),  # spike
         (0.5, "rogue@x", "auth_fail", 30)]  # never seen before, not declared
    )  # fmt: skip
    rep = ia.evaluate(_cfg(), rows, NOW)
    assert rep.ok and rep.identities == 3
    by = {(w.identity, w.event): w for w in rep.windows}
    assert by[("app@x", "key_request")].current == 10 and by[("app@x", "key_request")].baseline == 10.5
    assert 0.9 < by[("app@x", "key_request")].ratio < 1.1
    assert by[("batch@x", "key_request")].current == 200 and by[("batch@x", "key_request")].ratio == 40.0
    assert [(s.identity, s.event) for s in rep.spikes] == [("batch@x", "key_request"), ("rogue@x", "auth_fail")]
    assert rep.new_identities == ["rogue@x"] and rep.undeclared == ["rogue@x"]
    assert rep.auth_failures == {"rogue@x": 30}
    assert rep.newest_ts == pytest.approx(NOW - 0.5 * H)


def test_identity_small_counts_are_not_spikes_and_events_filter():
    rows = _rows([(1.5, "app@x", "key_request", 1), (0.5, "app@x", "key_request", 8), (0.5, "app@x", "weird", 500)])
    rep = ia.evaluate(_cfg(), rows, NOW)
    assert rep.spikes == []  # 8 < min_events, and 'weird' is not a counted event
    assert {w.event for w in rep.windows} == {"key_request"}
    rep2 = ia.evaluate(_cfg(events=["weird"]), rows, NOW)
    assert [w.event for w in rep2.spikes] == ["weird"]


def test_identity_ignores_future_old_and_malformed_rows():
    rows = [(NOW + 3600, "app@x", "key_request"), (NOW - 100 * H, "app@x", "key_request"), ("garbage", "app@x", "x"),
            (NOW - 10, "", "key_request"), (NOW - 10, "app@x", "key_request")]  # fmt: skip
    rep = ia.evaluate(_cfg(), rows, NOW)
    assert rep.identities == 1 and rep.windows[0].current == 1


def test_identity_cardinality_cap():
    rows = [(NOW - 10 - i, f"id{i}@x", "auth_ok") for i in range(50)] + [(NOW - 5, "id7@x", "auth_ok")] * 5
    rep = ia.evaluate(_cfg(max_identities=3), rows, NOW)
    assert rep.identities == 3 and "id7@x" in {w.identity for w in rep.windows}


def test_identity_parse_config_validation():
    assert ia.parse_config(None) is None
    with pytest.raises(SourceError):
        ia.parse_config({"source": {"type": "sql", "dsn": "sqlite:///x"}})  # no query
    with pytest.raises(SourceError):
        ia.parse_config({"source": {"type": "file", "path": "x"}, "columns": ["ts"]})


def test_identity_run_from_csv_and_metrics(tmp_path):
    path = tmp_path / "audit.csv"
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["when", "who", "what"])
        for r in _rows(
            [(1.5, "app@x", "key_request", 3), (0.5, "app@x", "key_request", 40), (0.5, "new@x", "auth_ok", 2)]
        ):
            w.writerow(r)
    cfg = _cfg(
        source={"type": "file", "path": str(path)}, columns=["when", "who", "what"], min_events=10, baseline_windows=1
    )
    rep = ia.run(cfg, now=NOW)
    assert rep.ok and [s.identity for s in rep.spikes] == ["app@x"] and rep.new_identities == ["new@x"]
    metrics.apply_identity_activity(rep, cfg.window_seconds)
    g = REGISTRY.get_sample_value
    assert g("voltage_identity_activity_up") == 1.0
    assert g("voltage_identity_events", {"identity": "app@x", "event": "key_request"}) == 40.0
    assert g("voltage_identity_events_baseline", {"identity": "app@x", "event": "key_request"}) == 3.0
    assert g("voltage_identity_activity_spike", {"identity": "app@x", "event": "key_request"}) == 1.0
    assert g("voltage_identity_new", {"identity": "new@x"}) == 1.0
    assert g("voltage_identity_undeclared", {"identity": "new@x"}) == 1.0
    assert g("voltage_identities_active") == 2.0
    # unreadable source -> up=0, nothing else touched
    bad = ia.run(_cfg(source={"type": "file", "path": str(tmp_path / "missing.csv")}), now=NOW)
    assert bad.ok is None
    metrics.apply_identity_activity(bad, 3600)
    assert g("voltage_identity_activity_up") == 0.0


# --------------------------------------------------------------------------- restore drills
def _drill(**over):
    d = {"name": "prod-identity-backup", "district": "prod", "max_age": "90d", "source": {"type": "file", "path": "x"}}
    d.update(over)
    return rd.parse_config([d])[0]


def test_drill_fresh_overdue_failed_never():
    day = 86400.0
    rows = [
        ("prod-identity-backup", NOW - 100 * day, "SUCCESS"),
        ("prod-identity-backup", NOW - 12 * day, "success"),
        ("dr-identity-backup", NOW - 190 * day, "PASS"),
        ("dr-identity-backup", NOW - 100 * day, "FAILED: master secret mismatch"),
        ("other", NOW - 1 * day, "SUCCESS"),
    ]
    fresh = rd.evaluate(_drill(), rows, NOW)
    assert fresh.ok and not fresh.overdue and not fresh.last_failed and fresh.attempts == 2
    assert fresh.last_success == pytest.approx(NOW - 12 * day) and "12 days ago" in fresh.detail
    dr = rd.evaluate(_drill(name="dr-identity-backup", district="dr"), rows, NOW)
    assert dr.ok is False and dr.overdue and dr.last_failed and "master secret mismatch" in dr.detail
    never = rd.evaluate(_drill(name="lab"), rows, NOW)
    assert never.ok is False and never.never_tested and never.overdue and never.last_success is None
    aliased = rd.evaluate(_drill(name="anything", match="other"), rows, NOW)
    assert aliased.ok


def test_drill_run_from_sqlite_and_metrics(tmp_path):
    db = tmp_path / "ops.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE drills (drill TEXT, finished_at TEXT, result TEXT)")
    c.executemany(
        "INSERT INTO drills VALUES (?,?,?)",
        [
            ("prod-identity-backup", "2026-09-01T10:00:00Z", "SUCCESS"),
            ("dr-identity-backup", "2026-01-01T10:00:00Z", "FAILED"),
        ],
    )
    c.commit()
    c.close()
    src = {"type": "sql", "dsn": f"sqlite:///{db}"}
    q = "SELECT drill, finished_at, result FROM drills"
    drills = rd.parse_config(
        [
            {"name": "prod-identity-backup", "district": "prod", "max_age": "90d", "source": src, "query": q},
            {"name": "dr-identity-backup", "district": "dr", "max_age": "90d", "source": src, "query": q},
            {
                "name": "ghost",
                "district": "x",
                "max_age": "1d",
                "source": {"type": "file", "path": str(tmp_path / "no.csv")},
            },
        ]
    )
    now = 1_757_800_000.0  # 2026-09-13T22:26Z: prod is 12 days old, dr never succeeded and last failed
    results = [rd.run(d, now=now) for d in drills]
    assert results[0].ok is True
    assert results[1].ok is False and results[1].never_tested and results[1].last_failed
    assert results[2].ok is None
    metrics.apply_restore_drills(results)
    g = REGISTRY.get_sample_value
    assert g("voltage_restore_drill_ok", {"drill": "prod-identity-backup", "district": "prod"}) == 1.0
    assert (
        g(
            "voltage_identity_backup_restore_tested_timestamp_seconds",
            {"drill": "prod-identity-backup", "district": "prod"},
        )
        > 0
    )
    assert g("voltage_restore_drill_last_failed", {"drill": "dr-identity-backup", "district": "dr"}) == 1.0
    assert (
        g("voltage_identity_backup_restore_tested_timestamp_seconds", {"drill": "dr-identity-backup", "district": "dr"})
        is None
    )
    assert g("voltage_restore_drill_up", {"drill": "ghost", "district": "x"}) == 0.0
    assert g("voltage_restore_drill_max_age_seconds", {"drill": "ghost", "district": "x"}) == 86400.0


def test_drill_parse_config_validation():
    with pytest.raises(SourceError):
        rd.parse_config([{"district": "x"}])
    with pytest.raises(SourceError):
        rd.parse_config([{"name": "a", "source": {"type": "sql", "dsn": "sqlite:///x"}}])  # no query


def test_seed_script_plants_the_demo_findings(tmp_path):
    seed = os.path.join(os.path.dirname(__file__), "..", "..", "demo", "seed_nonprod.py")
    db = tmp_path / "np.db"
    subprocess.run([sys.executable, seed, str(db)], check=True, capture_output=True)
    src = {"type": "sql", "dsn": f"sqlite:///{db}"}
    cfg = ia.parse_config(
        {
            "source": src,
            "query": "SELECT ts, identity, event FROM voltage_audit",
            "window": "1h",
            "baseline_windows": 24,
            "declared_identities": ["payments@demo.bank", "batch-etl@demo.bank", "probe@demo.bank"],
        }
    )
    rep = ia.run(cfg)
    assert rep.ok and {s.identity for s in rep.spikes} == {"batch-etl@demo.bank", "svc-reporting@demo.bank"}
    assert rep.undeclared == ["svc-reporting@demo.bank"] and rep.auth_failures["svc-reporting@demo.bank"] == 30
    q = "SELECT drill, finished_at, result FROM restore_drills"
    prod, dr = (rd.run(d) for d in rd.parse_config([
        {"name": "prod-identity-backup", "district": "prod", "max_age": "90d", "source": src, "query": q},
        {"name": "dr-identity-backup", "district": "dr", "max_age": "90d", "source": src, "query": q}]))  # fmt: skip
    assert prod.ok and not dr.ok and dr.last_failed and dr.overdue
