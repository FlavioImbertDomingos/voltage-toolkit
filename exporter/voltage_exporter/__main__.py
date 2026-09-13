from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time

from prometheus_client import start_http_server

from . import __version__
from .config import ConfigError, load
from .metrics import probe_loop

log = logging.getLogger("voltage_exporter")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="voltage-exporter", description="Synthetic-probe exporter for Voltage SecureData")
    ap.add_argument("-c", "--config", default=os.environ.get("VOLTAGE_EXPORTER_CONFIG", "/config/voltage-exporter.yml"))
    ap.add_argument("--once", action="store_true", help="run one probe cycle, print a summary, exit (no HTTP server)")
    ap.add_argument(
        "--log-format", choices=["text", "json"], help="override exporter.log_format (json: one event per line)"
    )
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        config = load(args.config)
    except (ConfigError, FileNotFoundError) as exc:
        print(f"voltage-exporter: configuration error: {exc}", file=sys.stderr)
        return 2
    from .structured import configure_logging

    configure_logging(config.log_level, args.log_format or config.log_format)

    if args.once:
        from .probes import run_target

        rc = 0
        results = []
        for t in config.targets:
            r = run_target(t)
            results.append(r)
            status = "ok" if r.policy_ok else "FAIL " + r.policy_error
            extra = f" ({len(r.policy.formats)} formats, district={r.policy.district!r})" if r.policy else ""
            print(f"[{t.name}] policy: {status}{extra}")
            if r.policy:
                from .lifecycle import support_end
                from .policy import MIN_FPE_DOMAIN, format_domain_size, is_efpe

                if r.policy.server_version:
                    se = support_end(r.policy.server_version, config.support_end)
                    tail = f", {se[0]} maintenance ends {time.strftime('%Y-%m-%d', time.gmtime(se[1]))}" if se else ""
                    print(f"[{t.name}] appliance: {r.policy.server_version}{tail}")
                for kt in r.policy.key_tables:
                    cur = kt.current or {}
                    print(
                        f"[{t.name}] key table {kt.name}: current #{kt.current_number} "
                        f"({cur.get('algorithm', '?')}-{cur.get('key_size', '?')}), {len(kt.keys)} version(s)"
                    )
                for f in r.policy.formats:
                    n = format_domain_size(f)
                    flags = []
                    if n is not None and n < MIN_FPE_DOMAIN:
                        flags.append(f"domain {n:,} < {MIN_FPE_DOMAIN:,} (SP 800-38G Rev. 1)")
                    if is_efpe(f):
                        flags.append("eFPE: not join-safe")
                    if flags:
                        print(f"[{t.name}] format {f['name']}: " + "; ".join(flags))
            for tk in r.tokenize:
                status = "ok" if tk.ok else f"FAIL [{tk.error_kind}] {tk.error}"
                lat = f" protect={tk.protect_seconds:.3f}s access={tk.access_seconds:.3f}s" if tk.ok else ""
                print(f"[{t.name}] tokenize {tk.spec.format}: {status}{lat}")
                rc = rc or (0 if tk.ok else 1)
            for ir in r.integrity:
                state = "ok" if ir.ok else ("FAIL" if ir.ok is False else "n/a")
                tgt = f"{ir.format}->{ir.against}" if ir.against else ir.format
                print(f"[{t.name}] integrity {ir.check} {tgt}: {state}{(' ' + ir.detail) if ir.detail else ''}")
                rc = rc or (1 if ir.ok is False else 0)
            for c in r.tls:
                days = int((c.not_after - time.time()) / 86400) if c.ok else 0
                print(f"[{t.name}] tls {c.host}:{c.port}: " + (f"ok, expires {days}d" if c.ok else f"FAIL {c.error}"))
            for url, up in r.keyservers.items():
                print(f"[{t.name}] keyserver {url}: {'up' if up else 'DOWN'}")
            if r.console_up is not None:
                print(f"[{t.name}] management console: {'up' if r.console_up else 'DOWN (control plane only)'}")
        from .fleet import evaluate as evaluate_fleet

        if config.coverage:
            from .coverage_runner import run_coverage

            rep, _ = run_coverage(config.coverage, results)
            if rep is None:
                print("[coverage] could not read the classification feed / data map")
                rc = 1
            else:
                t = rep.to_dict()["totals"]
                print(
                    f"[coverage] {rep.feed_rows} classified columns: {t['protected']} protected, "
                    f"{t['unmapped']} unmapped, {t['broken']} broken, {t['unknown']} unknown"
                )
                for c in rep.columns:
                    if c.state in ("unmapped", "broken"):
                        print(f"[coverage] {c.state.upper()} {c.row.qualified} ({c.row.classification}): {c.reason}")
                        rc = rc or 1
                for d, fmts in rep.dead_formats.items():
                    print(f"[coverage] dead formats in {d}: {', '.join(fmts)}")
                for e in rep.errors:
                    print(f"[coverage] error: {e}")
        if config.identity_activity:
            from . import identity_activity as ia

            ia_cfg = ia.parse_config(config.identity_activity)
            rep = ia.run(ia_cfg) if ia_cfg else None
            if rep is not None:
                if rep.ok is None:
                    print(f"[identity-activity] could not read the audit export: {rep.detail}")
                    rc = 1
                else:
                    print(f"[identity-activity] {rep.detail}")
                    for w in rep.spikes:
                        print(f"[identity-activity] SPIKE {w.identity} {w.event}: {w.current} vs {w.baseline}")
                    for ident, n in rep.auth_failures.items():
                        if n >= ia_cfg.auth_fail_threshold:
                            print(f"[identity-activity] AUTH FAILURES {ident}: {n} this window")
                    if rep.spikes or rep.undeclared:
                        rc = 1
        if config.restore_drills:
            from . import restore_drills as rd

            for d in rd.parse_config(config.restore_drills):
                r = rd.run(d)
                tag = "unreadable" if r.ok is None else ("ok" if r.ok else "OVERDUE" if r.overdue else "FAILED")
                print(f"[restore-drill] {d.name} ({d.district}): {tag} -- {r.detail}")
                if not r.ok:
                    rc = 1
        if config.sdm:
            from .sdm import parse_config, run_job_check, run_mask_check

            sc = parse_config(config.sdm)
            for m in (run_mask_check(x) for x in sc.masking):
                state = "ok" if m.ok else ("FAIL" if m.ok is False else "n/a")
                tail = f" {m.detail}" if m.detail else ""
                print(f"[sdm {m.check.name}] {m.check.kind}: {state} ({m.rows} rows){tail}")
                rc = rc or (1 if m.ok is False else 0)
            for j in (run_job_check(x) for x in sc.jobs):
                state = "ok" if j.ok else ("FAIL" if j.ok is False else "n/a")
                print(
                    f"[sdm {j.check.name}] jobs: {state} ({len(j.jobs)} job(s)){(' ' + j.detail) if j.detail else ''}"
                )
                for js in j.jobs:
                    when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(js.finished_at)) if js.finished_at else "?"
                    print(f"[sdm {j.check.name}]   {js.job}: {js.status} at {when}, rows={js.rows}")
                rc = rc or (1 if j.ok is False else 0)
        for c in evaluate_fleet(results):
            state = "agree" if c.ok else ("DIVERGED " + c.detail if c.ok is False else f"n/a ({c.detail})")
            print(f"[fleet {c.fleet}] {c.check}{(' ' + c.key) if c.key else ''} ({c.members} members): {state}")
            rc = rc or (1 if c.ok is False else 0)
        return rc

    log.info("voltage-exporter %s: %d target(s), interval %.0fs", __version__, len(config.targets), config.interval)
    stop = threading.Event()
    threading.Thread(target=probe_loop, args=(config, stop), daemon=True).start()
    start_http_server(config.port, addr=config.listen)
    log.info("listening on http://%s:%d/metrics", config.listen, config.port)
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
