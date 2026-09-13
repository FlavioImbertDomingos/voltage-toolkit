#!/usr/bin/env python3
"""Seed a pretend *masked* non-production database for the SDM checks (R8, R9).

    python demo/seed_nonprod.py /data/nonprod.db [--age-days 0]

What it plants, on purpose:
  customers.pan      masked card numbers -- and ONE row that still holds a planted canary
                     (the "masking job skipped a row" finding), visible from the first scrape
  orders.pan         the same customers' masked PANs, consistent with customers.pan
  customers.ssn      a constant value -- a fill-with-X job that "worked"
  sdm_job_history    one archive job that succeeded recently, one masking job whose last
                     success is 3 days old (stale) and whose latest run failed
  voltage_audit      a pretend appliance audit export (R10a): steady auth + key requests for two
                     application identities over 48 h, then in the LAST HOUR batch-etl@ pulls
                     keys 40x its baseline (a spike) and an undeclared identity fails auth 30x
The canary list lives in demo/canaries.txt; stdlib only.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import random
import sqlite3
import sys

CANARIES = [
    ln.strip()
    for ln in open(os.path.join(os.path.dirname(__file__), "canaries.txt"))
    if ln.strip() and not ln.startswith("#")
]


def mask_pan(pan: str) -> str:
    """Shape-preserving, deterministic, NOT cryptography: keep BIN + last 4, scramble the middle."""
    digits = pan.replace("-", "")
    mid = hashlib.sha256(b"demo-mask:" + digits.encode()).hexdigest()
    scrambled = "".join(str(int(c, 16) % 10) for c in mid[:6])
    return digits[:6] + scrambled + digits[-4:]


def main(path: str, age_days: int = 0) -> None:
    if os.path.exists(path):
        os.remove(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, name TEXT, pan TEXT, ssn TEXT);
        CREATE TABLE orders (order_id INTEGER PRIMARY KEY, customer_id INTEGER, pan TEXT,
                             amount REAL);
        CREATE TABLE voltage_audit (id INTEGER PRIMARY KEY, ts TEXT, identity TEXT, event TEXT,
                                    client TEXT);
        CREATE TABLE restore_drills (id INTEGER PRIMARY KEY, drill TEXT, finished_at TEXT,
                                     result TEXT, operator TEXT);
        CREATE TABLE sdm_job_history (id INTEGER PRIMARY KEY, job_name TEXT, status TEXT,
                                      started_at TEXT, finished_at TEXT, rows_processed INTEGER);
        """
    )
    rng = random.Random(42)
    pans = [f"4539{rng.randrange(10**12):012d}" for _ in range(40)]
    rows = [(i + 1, f"Customer {i + 1}", mask_pan(p), "XXX-XX-XXXX") for i, p in enumerate(pans)]
    rows[17] = (18, "Customer 18", CANARIES[0], "XXX-XX-XXXX")  # the row the masking job skipped
    c.executemany("INSERT INTO customers VALUES (?,?,?,?)", rows)
    orders = []
    for i, (cid, _, mpan, _) in enumerate(rows):
        for k in range(2):
            orders.append((i * 2 + k + 1, cid, mpan, round(rng.uniform(5, 500), 2)))
    c.executemany("INSERT INTO orders VALUES (?,?,?,?)", orders)

    now = dt.datetime.now(dt.UTC) - dt.timedelta(days=age_days)

    def ts(hours_ago: float) -> str:
        return (now - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

    c.executemany(
        "INSERT INTO sdm_job_history (job_name, status, started_at, finished_at, rows_processed)"
        " VALUES (?,?,?,?,?)",
        [
            ("archive-orders-2019", "SUCCESS", ts(30), ts(29.5), 1_204_331),
            ("archive-orders-2019", "SUCCESS", ts(6), ts(5.4), 1_198_002),
            ("mask-nonprod-refresh", "SUCCESS", ts(72), ts(71), 40),
            ("mask-nonprod-refresh", "FAILED", ts(20), ts(19.9), 0),
        ],
    )
    # --- appliance audit export (R10a): 48 h of steady control-plane activity, then a bad hour
    audit: list[tuple[str, str, str, str]] = []
    rng = random.Random(7)

    def spread(h_from: float, h_to: float, n: int, identity: str, event: str, client: str) -> None:
        for _ in range(n):
            audit.append((ts(rng.uniform(h_to, h_from)), identity, event, client))

    for h in range(48, 0, -1):  # hour h ago .. h-1 ago
        spread(h, h - 1, rng.randint(8, 12), "payments@demo.bank", "key_request", "pay-01")
        spread(h, h - 1, rng.randint(3, 5), "payments@demo.bank", "auth_ok", "pay-01")
        spread(h, h - 1, rng.randint(4, 6), "batch-etl@demo.bank", "key_request", "etl-07")
        spread(h, h - 1, 1, "batch-etl@demo.bank", "auth_ok", "etl-07")
        spread(h, h - 1, 2, "probe@demo.bank", "auth_ok", "voltage-exporter")
    # the last hour: batch-etl pulls keys for every format and epoch (a spike), and an identity
    # nobody declared fails authentication 30 times from an unknown client
    spread(1, 0, 200, "batch-etl@demo.bank", "key_request", "etl-07")
    spread(1, 0, 30, "svc-reporting@demo.bank", "auth_fail", "10.9.8.7")
    c.executemany("INSERT INTO voltage_audit (ts, identity, event, client) VALUES (?,?,?,?)", audit)

    # --- restore-drill evidence (R11): prod proven 12 days ago; DR's last attempt failed
    c.executemany(
        "INSERT INTO restore_drills (drill, finished_at, result, operator) VALUES (?,?,?,?)",
        [
            ("prod-identity-backup", ts(24 * 102), "SUCCESS", "f.domingos"),
            ("prod-identity-backup", ts(24 * 12), "SUCCESS", "f.domingos"),
            ("dr-identity-backup", ts(24 * 190), "SUCCESS", "ops-oncall"),
            ("dr-identity-backup", ts(24 * 100), "FAILED: master secret mismatch", "ops-oncall"),
        ],
    )
    conn.commit()
    conn.close()
    print(
        f"seeded {path}: {len(rows)} customers, {len(orders)} orders, 4 job history rows, "
        f"{len(audit)} audit events, 4 restore-drill rows"
    )


if __name__ == "__main__":
    main(
        sys.argv[1] if len(sys.argv) > 1 else "nonprod.db",
        int(sys.argv[3]) if len(sys.argv) > 3 else 0,
    )
