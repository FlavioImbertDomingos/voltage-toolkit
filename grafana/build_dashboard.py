#!/usr/bin/env python3
"""Generates grafana/dashboards/voltage.json. Edit this, not the JSON.

python grafana/build_dashboard.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "dashboards" / "voltage.json"
DS = {"type": "prometheus", "uid": "prometheus"}
_id = 0


def nid():
    global _id
    _id += 1
    return _id


def target(expr, legend="__auto", instant=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": f"R{nid()}"}
    if instant:
        t["instant"] = True
    return t


def thresholds(*steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


def stat(title, expr, x, y, w=4, h=4, thr=None, unit=None, mappings=None, decimals=None):
    fc = {"thresholds": thr or thresholds(("green", None))}
    if unit:
        fc["unit"] = unit
    if mappings:
        fc["mappings"] = mappings
    if decimals is not None:
        fc["decimals"] = decimals
    return {
        "id": nid(), "type": "stat", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": [target(expr, instant=True)],
        "fieldConfig": {"defaults": fc, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none"},
    }  # fmt: skip


def timeseries(title, targets, x, y, w=12, h=8, unit=None, stack=False, thr=None, max_=None):
    d = {"custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 12, "showPoints": "never",
                    "stacking": {"mode": "normal" if stack else "none"}}}  # fmt: skip
    if unit:
        d["unit"] = unit
    if max_ is not None:
        d["max"] = max_
        d["min"] = 0
    if thr:
        d["thresholds"] = thr
        d["custom"]["thresholdsStyle"] = {"mode": "line"}
    return {
        "id": nid(), "type": "timeseries", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": targets, "fieldConfig": {"defaults": d, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
    }  # fmt: skip


def table(title, expr, x, y, w=24, h=7, rename=None):
    return {
        "id": nid(), "type": "table", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": DS, "targets": [target(expr, instant=True)],
        "transformations": [{"id": "organize", "options": {
            "excludeByName": {"Time": True, "__name__": True, "job": True, "instance": True},
            "renameByName": rename or {}}}],
        "fieldConfig": {"defaults": {}, "overrides": []},
    }  # fmt: skip


def row(title, y):
    return {
        "id": nid(),
        "type": "row",
        "title": title,
        "collapsed": False,
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1},
        "panels": [],
    }


UPDOWN = [
    {
        "type": "value",
        "options": {"0": {"text": "DOWN", "color": "red"}, "1": {"text": "UP", "color": "green"}},
    }
]
OKBAD = [
    {
        "type": "value",
        "options": {"0": {"text": "FAIL", "color": "red"}, "1": {"text": "OK", "color": "green"}},
    }
]
SEL = 'target=~"$target"'

panels = [
    row("Can we tokenize right now?", 0),
    stat("Policy server", f"min(voltage_policy_up{{{SEL}}})", 0, 1, mappings=UPDOWN),
    stat("Key servers", f"min(voltage_keyserver_up{{{SEL}}})", 4, 1, mappings=UPDOWN),
    stat(
        "Round-trips OK",
        f"sum(voltage_tokenize_success{{{SEL}}}) / count(voltage_tokenize_success{{{SEL}}})",
        8,
        1,
        unit="percentunit",
        thr=thresholds(("red", None), ("orange", 0.99), ("green", 1)),
    ),  # fmt: skip
    stat("Data integrity", f"min(voltage_tokenize_roundtrip_ok{{{SEL}}})", 12, 1, mappings=OKBAD),
    stat(
        "p95 protect (10m)",
        f"max(voltage:protect_p95_seconds_10m{{{SEL}}})",
        16,
        1,
        unit="s",
        decimals=3,
        thr=thresholds(("green", None), ("orange", 0.25), ("red", 0.5)),
    ),  # fmt: skip
    stat(
        "Error rate (10m)",
        f"max(voltage:tokenize_error_ratio_10m{{{SEL}}})",
        20,
        1,
        unit="percentunit",
        decimals=1,
        thr=thresholds(("green", None), ("orange", 0.01), ("red", 0.05)),
    ),  # fmt: skip
    stat(
        "Nearest cert expiry",
        f"min(voltage:certificate_days_until_expiry{{{SEL}}})",
        0,
        5,
        w=4,
        unit="d",
        decimals=0,
        thr=thresholds(("red", None), ("orange", 7), ("yellow", 30), ("green", 90)),
    ),  # fmt: skip
    stat("Formats in policy", f"sum(voltage_policy_formats{{{SEL}}})", 4, 5, w=4),
    stat(
        "Policy changes (24h)",
        f"sum(increase(voltage_policy_changes_total{{{SEL}}}[24h]))",
        8,
        5,
        w=4,
        thr=thresholds(("green", None), ("orange", 1)),
    ),  # fmt: skip
    stat(
        "Probe cycle",
        f"max(voltage_probe_cycle_seconds{{{SEL}}})",
        12,
        5,
        w=4,
        unit="s",
        decimals=2,
    ),
    stat(
        "Last probe",
        f"time() - max(voltage_probe_last_run_timestamp_seconds{{{SEL}}})",
        16,
        5,
        w=4,
        unit="s",
        decimals=0,
        thr=thresholds(("green", None), ("orange", 120), ("red", 300)),
    ),  # fmt: skip
    stat("Silent-corruption checks", f"min(voltage_integrity_ok{{{SEL}}})", 20, 5, mappings=OKBAD),
    row("Latency & errors", 9),
    timeseries(
        "protect latency p50 / p95 / p99",
        [
            target(
                f"histogram_quantile(0.50, sum by (le) (rate(voltage_protect_seconds_bucket{{{SEL}}}[5m])))",
                "p50",
            ),
            target(
                f"histogram_quantile(0.95, sum by (le) (rate(voltage_protect_seconds_bucket{{{SEL}}}[5m])))",
                "p95",
            ),
            target(
                f"histogram_quantile(0.99, sum by (le) (rate(voltage_protect_seconds_bucket{{{SEL}}}[5m])))",
                "p99",
            ),
        ],
        0,
        10,
        unit="s",
        thr=thresholds(("transparent", None), ("red", 0.5)),
    ),  # fmt: skip
    timeseries(
        "access latency p95 by format",
        [
            target(f"voltage:access_p95_seconds_10m{{{SEL}}}", "{{target}} {{format}}"),
        ],
        12,
        10,
        unit="s",
    ),  # fmt: skip
    timeseries(
        "Error ratio by format (10m)",
        [
            target(f"voltage:tokenize_error_ratio_10m{{{SEL}}}", "{{target}} {{format}}"),
        ],
        0,
        18,
        unit="percentunit",
        max_=1,
        thr=thresholds(("transparent", None), ("red", 0.05)),
    ),  # fmt: skip
    timeseries(
        "Failures by kind (per 10m)",
        [
            target(
                f"sum by (kind) (increase(voltage_tokenize_errors_total{{{SEL}}}[10m]))", "{{kind}}"
            ),
        ],
        12,
        18,
        stack=True,
    ),  # fmt: skip
    row("Configuration & certificates", 26),
    table("Formats offered by the policy", f"voltage_policy_format{{{SEL}}}", 0, 27, w=12, h=8),
    table(
        "Certificates: days to expiry",
        f"sort(voltage:certificate_days_until_expiry{{{SEL}}})",
        12,
        27,
        w=12,
        h=8,
        rename={"Value": "days"},
    ),  # fmt: skip
    table("Policy", f"voltage_policy_info{{{SEL}}}", 0, 35, h=4),
    row("What the policy says about the crypto", 39),
    stat(
        "Formats under NIST's 10^6 domain floor",
        f"sum(voltage_format_below_minimum_domain{{{SEL}}}) or vector(0)",
        0,
        40,
        thr=thresholds(("green", None), ("orange", 1)),
    ),
    stat(
        "eFPE formats (not join-safe)",
        f"count(voltage_policy_format_efpe{{{SEL}}}) or vector(0)",
        4,
        40,
    ),
    stat(
        "Key rotations (24h)",
        f"sum(increase(voltage_key_rotations_total{{{SEL}}}[24h])) or vector(0)",
        8,
        40,
    ),
    stat(
        "Weakest current key (bits)",
        f"min(voltage_key_current_size_bits{{{SEL}}} > 0)",
        12,
        40,
        thr=thresholds(("red", None), ("green", 256)),
    ),
    stat(
        "Days of vendor support left",
        f"min(voltage:support_days_remaining{{{SEL}}})",
        16,
        40,
        w=8,
        decimals=0,
        thr=thresholds(("red", None), ("orange", 0), ("green", 180)),
    ),
    table(
        "Key tables",
        f"voltage_key_table_current_number{{{SEL}}}",
        0,
        44,
        w=12,
        h=7,
        rename={"Value": "currentNumber"},
    ),
    table(
        "FPE domain size per format",
        f"sort(voltage_format_domain_size{{{SEL}}})",
        12,
        44,
        w=12,
        h=7,
        rename={"Value": "domain"},
    ),
    table("Appliance version", f"voltage_appliance_version_info{{{SEL}}}", 0, 51, h=4),
    row("Fleet agreement — do all members give the same answers?", 55),
    stat("Tokens agree", 'min(voltage_fleet_agreement{check="token"})', 0, 56, mappings=OKBAD),
    stat("Policy agrees", 'min(voltage_fleet_agreement{check="policy"})', 4, 56, mappings=OKBAD),
    stat(
        "Key tables agree", 'min(voltage_fleet_agreement{check="key_table"})', 8, 56, mappings=OKBAD
    ),
    stat("Versions agree", 'min(voltage_fleet_agreement{check="version"})', 12, 56, mappings=OKBAD),
    table("Diverged members", "voltage_fleet_member_diverged == 1", 0, 60, h=6),
    row("Coverage — is every classified sensitive column protected?", 66),
    stat(
        "Unmapped sensitive columns",
        'sum(voltage_coverage_columns{state="unmapped"}) or vector(0)',
        0,
        67,
        thr=thresholds(("green", None), ("orange", 1)),
    ),
    stat(
        "Broken mappings",
        'sum(voltage_coverage_columns{state="broken"}) or vector(0)',
        4,
        67,
        thr=thresholds(("green", None), ("red", 1)),
    ),
    stat(
        "Protected columns", 'sum(voltage_coverage_columns{state="protected"}) or vector(0)', 8, 67
    ),
    stat("Dead formats", "count(voltage_coverage_dead_format == 1) or vector(0)", 12, 67),
    stat(
        "Feed age (days)",
        "voltage:coverage_feed_age_days",
        16,
        67,
        w=8,
        decimals=1,
        thr=thresholds(("green", None), ("orange", 7), ("red", 30)),
    ),
    table("Columns not protected", "voltage_coverage_column_info", 0, 71, h=7),
]

dashboard = {
    "uid": "voltage-securedata", "title": "Voltage SecureData — tokenization health",
    "tags": ["voltage", "tokenization", "securedata", "voltage-toolkit"], "timezone": "browser",
    "editable": True, "refresh": "30s", "schemaVersion": 39, "version": 1, "graphTooltip": 1,
    "time": {"from": "now-3h", "to": "now"},
    "templating": {"list": [{
        "name": "target", "label": "Target", "type": "query", "datasource": DS,
        "query": {"query": "label_values(voltage_policy_up, target)", "refId": "var"},
        "definition": "label_values(voltage_policy_up, target)", "refresh": 2, "includeAll": True, "multi": True,
        "allValue": ".*", "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "sort": 1,
    }]},
    "annotations": {"list": [{
        "name": "Alerts", "datasource": DS, "enable": True, "iconColor": "red",
        "expr": 'ALERTS{alertstate="firing", alertname=~"Voltage.*"}', "titleFormat": "{{alertname}}",
        "textFormat": "{{target}} {{format}} {{host}}", "step": "15s",
    }]},
    "panels": panels,
}  # fmt: skip
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(dashboard, indent=2) + "\n")
print(f"wrote {OUT} ({len(panels)} panels)")
