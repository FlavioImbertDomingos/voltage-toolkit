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
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        config = load(args.config)
    except (ConfigError, FileNotFoundError) as exc:
        print(f"voltage-exporter: configuration error: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    if args.once:
        from .probes import run_target

        rc = 0
        for t in config.targets:
            r = run_target(t)
            status = "ok" if r.policy_ok else "FAIL " + r.policy_error
            extra = f" ({len(r.policy.formats)} formats, district={r.policy.district!r})" if r.policy else ""
            print(f"[{t.name}] policy: {status}{extra}")
            for tk in r.tokenize:
                status = "ok" if tk.ok else f"FAIL [{tk.error_kind}] {tk.error}"
                lat = f" protect={tk.protect_seconds:.3f}s access={tk.access_seconds:.3f}s" if tk.ok else ""
                print(f"[{t.name}] tokenize {tk.spec.format}: {status}{lat}")
                rc = rc or (0 if tk.ok else 1)
            for c in r.tls:
                days = int((c.not_after - time.time()) / 86400) if c.ok else 0
                print(f"[{t.name}] tls {c.host}:{c.port}: " + (f"ok, expires {days}d" if c.ok else f"FAIL {c.error}"))
            for url, up in r.keyservers.items():
                print(f"[{t.name}] keyserver {url}: {'up' if up else 'DOWN'}")
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
