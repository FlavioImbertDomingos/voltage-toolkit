"""Talk to Voltage SecureData: policy download, Web Services protect/access, TLS certs.

Two Web Services flavours are supported:

* **REST** — `POST <ws_url>/vibesimple/rest/v1/protect` and `/access` with a JSON body
  `{"identity": ..., "format": ..., "data": [...]}` and HTTP Basic credentials
  (identity + shared secret, or username + password). Set `auth_in_body: true`
  to send `sharedSecret` / `username` / `password` inside the JSON instead.
* **SOAP** — `POST <ws_url>/vibesimple/services/VibeSimpleSOAP` with the
  `ProtectFormattedData` / `AccessFormattedData` operations.

OpenText's Web Services guide is behind a support login, so the REST field names
and paths are configurable; the mock server implements exactly what is documented
here. If your appliance answers differently, override `rest_path_*` / `soap_path`
and open an issue with a (redacted) sample so the defaults can be corrected.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse
from xml.sax.saxutils import escape

import requests
from cryptography import x509

from .config import Target


class VoltageError(Exception):
    pass


@dataclass
class Timed:
    value: object
    seconds: float


_SOAP_NS = "http://voltage.com/vibesimple"  # namespace used by the mock; override-able if yours differs


class VoltageClient:
    def __init__(self, target: Target):
        self.t = target
        self.session = requests.Session()
        # verify is passed per request: a session-level False is overridden by REQUESTS_CA_BUNDLE
        self.session.headers["User-Agent"] = "voltage-exporter"
        if target.verify_tls is False:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------ policy
    def fetch_policy(self) -> Timed:
        started = time.perf_counter()
        r = self.session.get(self.t.policy_url, timeout=self.t.timeout, verify=self.t.verify_tls)
        secs = time.perf_counter() - started
        if r.status_code >= 400:
            raise VoltageError(f"policy GET -> HTTP {r.status_code}")
        return Timed(r.content, secs)

    # ------------------------------------------------------------ auth
    def _basic_auth(self) -> tuple[str, str]:
        if self.t.auth_method == "password":
            return (self.t.username or self.t.identity, self.t.secret)
        return (self.t.identity, self.t.secret)

    def _body_auth(self) -> dict:
        if self.t.auth_method == "password":
            return {"username": self.t.username or self.t.identity, "password": self.t.secret}
        return {"sharedSecret": self.t.secret}

    # ------------------------------------------------------------ protect / access
    def protect(self, fmt: str, value: str, identity: str | None = None) -> Timed:
        return self._op("protect", fmt, value, identity)

    def access(self, fmt: str, value: str, identity: str | None = None) -> Timed:
        return self._op("access", fmt, value, identity)

    def _op(self, op: str, fmt: str, value: str, identity: str | None) -> Timed:
        ident = identity or self.t.identity
        if self.t.api == "soap":
            return self._soap(op, fmt, value, ident)
        return self._rest(op, fmt, value, ident)

    def _rest(self, op: str, fmt: str, value: str, identity: str) -> Timed:
        path = self.t.rest_path_protect if op == "protect" else self.t.rest_path_access
        body: dict = {"identity": identity, "format": fmt, "data": [value]}
        kwargs: dict = {"json": body, "timeout": self.t.timeout, "verify": self.t.verify_tls}
        if self.t.auth_in_body:
            body.update(self._body_auth())
        else:
            kwargs["auth"] = self._basic_auth()
        started = time.perf_counter()
        r = self.session.post(self.t.ws_url + path, **kwargs)
        secs = time.perf_counter() - started
        if r.status_code >= 400:
            raise VoltageError(f"{op} -> HTTP {r.status_code}: {r.text[:120]}")
        try:
            payload = r.json()
        except ValueError as exc:
            raise VoltageError(f"{op}: non-JSON response") from exc
        out = _first_string_list(payload)
        if not out:
            raise VoltageError(f"{op}: no data in response: {str(payload)[:120]}")
        return Timed(out[0], secs)

    def _soap(self, op: str, fmt: str, value: str, identity: str) -> Timed:
        operation = "ProtectFormattedData" if op == "protect" else "AccessFormattedData"
        auth_xml = (
            f"<sharedSecret>{escape(self.t.secret)}</sharedSecret>"
            if self.t.auth_method != "password"
            else (
                f"<username>{escape(self.t.username or identity)}</username>"
                f"<password>{escape(self.t.secret)}</password>"
            )
        )
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            f'xmlns:vs="{_SOAP_NS}"><soapenv:Body><vs:{operation}>'
            f"<identity>{escape(identity)}</identity>{auth_xml}"
            f"<format>{escape(fmt)}</format><data>{escape(value)}</data>"
            f"</vs:{operation}></soapenv:Body></soapenv:Envelope>"
        )
        started = time.perf_counter()
        r = self.session.post(
            self.t.ws_url + self.t.soap_path,
            data=envelope.encode(),
            headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": operation},
            timeout=self.t.timeout,
            verify=self.t.verify_tls,
        )
        secs = time.perf_counter() - started
        if r.status_code >= 400:
            fault = re.search(r"<faultstring>(.*?)</faultstring>", r.text, re.S)
            raise VoltageError(f"{op} SOAP -> HTTP {r.status_code}: {fault.group(1) if fault else r.text[:120]}")
        m = re.search(r"<(?:\w+:)?data>(.*?)</(?:\w+:)?data>", r.text, re.S)
        if not m:
            raise VoltageError(f"{op} SOAP: no <data> in response")
        return Timed(m.group(1), secs)

    # ------------------------------------------------------------ tls
    @staticmethod
    def certificate(host: str, port: int = 443, timeout: float = 5.0) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
        cert = x509.load_der_x509_certificate(der)
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_after": cert.not_valid_after_utc.timestamp(),
            "not_before": cert.not_valid_before_utc.timestamp(),
            "tls_version": version,
        }


def host_port(url_or_host: str, default_port: int = 443) -> tuple[str, int]:
    if "://" in url_or_host:
        u = urlparse(url_or_host)
        return u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    host, _, port = url_or_host.rpartition(":")
    if not host:
        return url_or_host, default_port
    return host, int(port)


def _first_string_list(payload) -> list[str]:
    """Voltage REST responses carry the results in a list; find it wherever it is."""
    if isinstance(payload, list) and payload and all(isinstance(x, str) for x in payload):
        return payload
    if isinstance(payload, dict):
        for key in ("data", "protectedData", "accessedData", "results", "result"):
            v = payload.get(key)
            if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                return v
            if isinstance(v, str):
                return [v]
        for v in payload.values():
            found = _first_string_list(v)
            if found:
                return found
    return []


def now_ts() -> float:
    return datetime.now(UTC).timestamp()
