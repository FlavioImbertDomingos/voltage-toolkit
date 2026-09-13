"""Configuration.

    exporter:
      port: 9743
      interval_seconds: 30          # how often every probe runs (independent of Prometheus scrapes)
      support_end:                  # optional: extend the built-in appliance support-lifecycle table
        "7.0.4": 2027-11-30         #   version prefix -> end-of-maintenance date (from your support portal)

    sdm:                            # optional: Structured Data Manager -- masked data and batch jobs (docs/SDM.md)
      masking:
        - name: nonprod-cards-pan
          kind: leak                                    # leak | consistency | constant
          source: {type: sql, dsn: "sqlite:////data/nonprod.db"}
          query: "SELECT pan FROM customers"
          canary_file: /config/canaries.txt             # values planted in prod that must never appear masked
        - name: nonprod-cards-ri
          kind: consistency
          source: {type: sql, dsn: "sqlite:////data/nonprod.db"}
          query: "SELECT c.customer_id, c.pan, o.pan FROM customers c JOIN orders o USING (customer_id)"
      jobs:
        - name: sdm-jobs
          source: {type: sql, dsn: "sqlite:////data/nonprod.db"}
          query: "SELECT job_name, status, finished_at, rows_processed FROM sdm_job_history"
          expect_every: 24h

    coverage:                       # optional: is every classified sensitive column actually protected?
      classification_csv: /config/classification.csv     # system,schema,table,column,classification,confidence
      data_map: /config/voltage-data-map.yml             # column -> district/format/identities (config-as-code)
      desired_state: /config/voltage-config.yml          # optional: enables identity checks
      min_confidence: 0.8
      sensitive_classes: [PAN, SSN, CVV]                  # optional filter; default: every row
      max_named_columns: 50                               # cap on the per-column info series

    targets:
      - name: prod
        policy_url: https://voltage-pp-0000.demo.bank/policy/clientPolicy.xml
        ws_url: https://voltage-pp-0000.demo.bank          # Web Services host (REST/SOAP under /vibesimple)
        api: rest                                          # rest | soap
        identity: probe@demo.bank
        auth:
          method: shared_secret                            # shared_secret | password
          secret_env: VOLTAGE_SHARED_SECRET                # or secret_file
          # username: monitor  (for method: password; username defaults to identity)
        verify_tls: true                                   # true | false | /path/to/ca.pem
        timeout_seconds: 10
        probes:
          - {format: CC,        sample: "4111111111111111"}
          - {format: SSN,       sample: "123-45-6789"}
          - {format: CC-ST-64O, sample: "4111111111111111", tokenization: true}
        extra_tls_hosts: ["voltage-ks-0000.demo.bank:443"] # additional certs to watch
        labels: {site: phx}
        fleet: prod                                        # targets sharing a fleet name must agree:
                                                           #   same policy hash, same key numbers, same tokens
        integrity:                                         # silent-corruption probes (all default true)
          determinism: true                                #   protect(x) == protect(x)  (skipped for eFPE)
          double_protect: true                             #   access(protect(protect(x))) == protect(x)
          format_isolation: true                           #   access under the *wrong* format must not yield x
          isolation_pairs: [[CC, SSN]]                     #   optional; default pairs each FPE probe with the next

Secrets come from env vars or files, never from the YAML.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    pass


@dataclass
class ProbeSpec:
    format: str
    sample: str
    tokenization: bool = False
    district: str = ""
    identity: str | None = None  # override the target identity


@dataclass
class Target:
    name: str
    policy_url: str
    ws_url: str
    identity: str
    secret: str
    auth_method: str = "shared_secret"  # shared_secret | password
    username: str | None = None
    api: str = "rest"
    rest_path_protect: str = "/vibesimple/rest/v1/protect"
    rest_path_access: str = "/vibesimple/rest/v1/access"
    soap_path: str = "/vibesimple/services/VibeSimpleSOAP"
    auth_in_body: bool = False  # put credentials in the JSON body instead of HTTP Basic
    verify_tls: bool | str = True
    timeout: float = 10.0
    probes: list[ProbeSpec] = field(default_factory=list)
    extra_tls_hosts: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    fleet: str = ""  # targets with the same fleet name are expected to agree (R4 / R15)
    integrity_determinism: bool = True
    integrity_double_protect: bool = True
    integrity_format_isolation: bool = True
    isolation_pairs: list[tuple[str, str]] = field(default_factory=list)  # (protect format, access format)


@dataclass
class CoverageConfig:
    classification_csv: str
    data_map: str
    desired_state: str = ""
    min_confidence: float = 0.0
    sensitive_classes: list[str] = field(default_factory=list)
    max_named_columns: int = 50


@dataclass
class Config:
    targets: list[Target]
    port: int = 9743
    listen: str = "0.0.0.0"
    interval: float = 30.0
    log_level: str = "INFO"
    support_end: dict = field(default_factory=dict)  # version prefix -> ISO date | {release, end}
    coverage: CoverageConfig | None = None
    sdm: dict | None = None  # raw `sdm:` block; parsed by sdm.parse_config (masking checks, jobs)


def _secret(entry: dict, name: str, key: str = "secret") -> str:
    auth = entry.get("auth") or {}
    if auth.get(f"{key}_file"):
        p = Path(auth[f"{key}_file"])
        if not p.exists():
            raise ConfigError(f"[{name}] auth.{key}_file {p} does not exist")
        return p.read_text().strip()
    if auth.get(f"{key}_env"):
        v = os.environ.get(auth[f"{key}_env"])
        if not v:
            raise ConfigError(f"[{name}] env var {auth[f'{key}_env']} is not set")
        return v
    if auth.get(key):
        return str(auth[key])
    raise ConfigError(f"[{name}] auth needs {key}_env, {key}_file or {key}")


def _bool_or_path(v: Any, default: bool = True) -> bool | str:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip()
    if s.lower() in ("true", "yes", "1", "on"):
        return True
    if s.lower() in ("false", "no", "0", "off"):
        return False
    return s  # a CA bundle path


def _target(entry: dict) -> Target:
    name = entry.get("name")
    if not name:
        raise ConfigError("every target needs a name")
    for key in ("policy_url", "identity"):
        if not entry.get(key):
            raise ConfigError(f"[{name}] needs '{key}'")
    policy_url = str(entry["policy_url"])
    ws_url = str(entry.get("ws_url") or policy_url.split("/policy/")[0]).rstrip("/")
    auth = entry.get("auth") or {}
    method = str(auth.get("method", "shared_secret"))
    probes = []
    for p in entry.get("probes") or []:
        if not p.get("format") or p.get("sample") is None:
            raise ConfigError(f"[{name}] every probe needs 'format' and 'sample'")
        probes.append(
            ProbeSpec(
                format=str(p["format"]),
                sample=str(p["sample"]),
                tokenization=bool(p.get("tokenization", False)),
                district=str(p.get("district", "")),
                identity=p.get("identity"),
            )
        )
    integ = entry.get("integrity") or {}
    pairs: list[tuple[str, str]] = []
    for pair in integ.get("isolation_pairs") or []:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ConfigError(f"[{name}] integrity.isolation_pairs entries must be [protect_format, access_format]")
        pairs.append((str(pair[0]), str(pair[1])))
    return Target(
        name=str(name),
        policy_url=policy_url,
        ws_url=ws_url,
        identity=str(entry["identity"]),
        secret=_secret(entry, str(name)),
        auth_method=method,
        username=auth.get("username"),
        api=str(entry.get("api", "rest")).lower(),
        rest_path_protect=str(entry.get("rest_path_protect", "/vibesimple/rest/v1/protect")),
        rest_path_access=str(entry.get("rest_path_access", "/vibesimple/rest/v1/access")),
        soap_path=str(entry.get("soap_path", "/vibesimple/services/VibeSimpleSOAP")),
        auth_in_body=bool(entry.get("auth_in_body", False)),
        verify_tls=_bool_or_path(entry.get("verify_tls"), True) if not entry.get("ca_cert") else str(entry["ca_cert"]),
        timeout=float(entry.get("timeout_seconds", 10)),
        probes=probes,
        extra_tls_hosts=[str(h) for h in entry.get("extra_tls_hosts") or []],
        labels={str(k): str(v) for k, v in (entry.get("labels") or {}).items()},
        fleet=str(entry.get("fleet") or ""),
        integrity_determinism=bool(integ.get("determinism", True)),
        integrity_double_protect=bool(integ.get("double_protect", True)),
        integrity_format_isolation=bool(integ.get("format_isolation", True)),
        isolation_pairs=pairs,
    )


def load(path: str | Path) -> Config:
    with open(path) as fh:
        raw = yaml.safe_load(fh) or {}
    targets = [_target(t) for t in raw.get("targets") or []]
    if not targets:
        raise ConfigError(f"{path}: 'targets' is empty")
    ex = raw.get("exporter") or {}
    cov = None
    if raw.get("coverage"):
        c = raw["coverage"]
        for key in ("classification_csv", "data_map"):
            if not c.get(key):
                raise ConfigError(f"coverage needs '{key}'")
        cov = CoverageConfig(
            classification_csv=str(c["classification_csv"]),
            data_map=str(c["data_map"]),
            desired_state=str(c.get("desired_state") or ""),
            min_confidence=float(c.get("min_confidence", 0.0)),
            sensitive_classes=[str(x) for x in (c.get("sensitive_classes") or [])],
            max_named_columns=int(c.get("max_named_columns", 50)),
        )
    return Config(
        targets=targets,
        port=int(os.environ.get("VOLTAGE_EXPORTER_PORT", ex.get("port", 9743))),
        listen=str(ex.get("listen", "0.0.0.0")),
        interval=float(os.environ.get("VOLTAGE_EXPORTER_INTERVAL", ex.get("interval_seconds", 30))),
        log_level=str(os.environ.get("VOLTAGE_EXPORTER_LOG_LEVEL", ex.get("log_level", "INFO"))),
        support_end={str(k): v for k, v in (ex.get("support_end") or {}).items()},
        coverage=cov,
        sdm=raw.get("sdm") or None,
    )
