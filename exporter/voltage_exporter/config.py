"""Configuration.

    exporter:
      port: 9743
      interval_seconds: 30          # how often every probe runs (independent of Prometheus scrapes)

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


@dataclass
class Config:
    targets: list[Target]
    port: int = 9743
    listen: str = "0.0.0.0"
    interval: float = 30.0
    log_level: str = "INFO"


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
    )


def load(path: str | Path) -> Config:
    with open(path) as fh:
        raw = yaml.safe_load(fh) or {}
    targets = [_target(t) for t in raw.get("targets") or []]
    if not targets:
        raise ConfigError(f"{path}: 'targets' is empty")
    ex = raw.get("exporter") or {}
    return Config(
        targets=targets,
        port=int(os.environ.get("VOLTAGE_EXPORTER_PORT", ex.get("port", 9743))),
        listen=str(ex.get("listen", "0.0.0.0")),
        interval=float(os.environ.get("VOLTAGE_EXPORTER_INTERVAL", ex.get("interval_seconds", 30))),
        log_level=str(os.environ.get("VOLTAGE_EXPORTER_LOG_LEVEL", ex.get("log_level", "INFO"))),
    )
