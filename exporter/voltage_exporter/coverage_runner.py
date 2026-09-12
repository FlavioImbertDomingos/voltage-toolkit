"""Read the coverage inputs from disk and evaluate them against this cycle's live policies.

Kept apart from coverage.py so that module stays stdlib-only and identical to the Ansible
collection's copy; this file is the exporter's glue (files, YAML, logging)."""

from __future__ import annotations

import logging
import os

import yaml

from . import coverage as cov
from .config import CoverageConfig
from .probes import TargetResult

log = logging.getLogger(__name__)


def run_coverage(cfg: CoverageConfig, results: list[TargetResult]) -> tuple[cov.CoverageReport | None, float | None]:
    try:
        with open(cfg.classification_csv, encoding="utf-8") as fh:
            feed_text = fh.read()
        mtime = os.path.getmtime(cfg.classification_csv)
        with open(cfg.data_map, encoding="utf-8") as fh:
            map_doc = yaml.safe_load(fh) or {}
        desired = None
        if cfg.desired_state:
            with open(cfg.desired_state, encoding="utf-8") as fh:
                desired = yaml.safe_load(fh) or {}
    except OSError as exc:
        log.error("coverage: cannot read inputs: %s", exc)
        return None, None
    except yaml.YAMLError as exc:
        log.error("coverage: bad YAML: %s", exc)
        return None, None

    feed, ferr = cov.parse_feed(feed_text)
    entries, merr = cov.parse_data_map(map_doc)
    # live policies, keyed by the district the policy itself declares
    policy_formats: dict[str, list[str]] = {}
    for r in results:
        if r.policy and r.policy.district:
            policy_formats.setdefault(r.policy.district, r.policy.format_names)
    identities = cov.identities_from_desired_state(desired) if desired is not None else None
    rep = cov.evaluate(
        feed,
        entries,
        policy_formats,
        identities,
        min_confidence=cfg.min_confidence,
        sensitive_classes=cfg.sensitive_classes or None,
    )
    rep.errors = ferr + merr + rep.errors
    return rep, mtime
