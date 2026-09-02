# -*- coding: utf-8 -*-
# Copyright (c) 2026 Flavio Domingos
# Apache-2.0
"""Minimal Voltage SecureData client for Ansible modules (stdlib + ansible.module_utils.urls only).

Mirrors exporter/voltage_exporter/client.py: policy download, REST and SOAP protect/access.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # noqa: F821

import base64
import json
import re
import time
from xml.sax.saxutils import escape

from ansible.module_utils.urls import open_url

REST_PROTECT = "/vibesimple/rest/v1/protect"
REST_ACCESS = "/vibesimple/rest/v1/access"
SOAP_PATH = "/vibesimple/services/VibeSimpleSOAP"
SOAP_NS = "http://voltage.com/vibesimple"


class VoltageClientError(Exception):
    pass


def fetch_policy(url, validate_certs=True, ca_path=None, timeout=10):
    """Return (xml_bytes, seconds)."""
    started = time.time()
    try:
        resp = open_url(url, validate_certs=validate_certs, ca_path=ca_path, timeout=timeout, http_agent="ansible-voltage")
        data = resp.read()
    except Exception as exc:  # noqa: BLE001
        raise VoltageClientError("policy GET %s failed: %s" % (url, exc))
    return data, time.time() - started


def _first_string_list(payload):
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


def ws_call(op, ws_url, identity, secret, fmt, value, api="rest", auth_method="shared_secret", username=None,
            auth_in_body=False, validate_certs=True, ca_path=None, timeout=10, rest_path=None, soap_path=SOAP_PATH):
    """protect or access one value. Returns (result_string, seconds)."""
    if api == "soap":
        return _soap(op, ws_url, identity, secret, fmt, value, auth_method, username, validate_certs, ca_path, timeout, soap_path)
    path = rest_path or (REST_PROTECT if op == "protect" else REST_ACCESS)
    body = {"identity": identity, "format": fmt, "data": [value]}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if auth_in_body:
        if auth_method == "password":
            body.update({"username": username or identity, "password": secret})
        else:
            body["sharedSecret"] = secret
    else:
        user = (username or identity) if auth_method == "password" else identity
        token = base64.b64encode(("%s:%s" % (user, secret)).encode()).decode()
        headers["Authorization"] = "Basic " + token
    started = time.time()
    try:
        resp = open_url(ws_url.rstrip("/") + path, method="POST", data=json.dumps(body).encode(), headers=headers,
                        validate_certs=validate_certs, ca_path=ca_path, timeout=timeout, http_agent="ansible-voltage")
        raw = resp.read()
    except Exception as exc:  # noqa: BLE001
        raise VoltageClientError("%s failed: %s" % (op, _short(exc)))
    secs = time.time() - started
    try:
        payload = json.loads(raw.decode())
    except ValueError:
        raise VoltageClientError("%s: non-JSON response" % op)
    out = _first_string_list(payload)
    if not out:
        raise VoltageClientError("%s: no data in response" % op)
    return out[0], secs


def _soap(op, ws_url, identity, secret, fmt, value, auth_method, username, validate_certs, ca_path, timeout, soap_path):
    operation = "ProtectFormattedData" if op == "protect" else "AccessFormattedData"
    if auth_method == "password":
        auth_xml = "<username>%s</username><password>%s</password>" % (escape(username or identity), escape(secret))
    else:
        auth_xml = "<sharedSecret>%s</sharedSecret>" % escape(secret)
    envelope = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vs="%s">'
        "<soapenv:Body><vs:%s><identity>%s</identity>%s<format>%s</format><data>%s</data></vs:%s>"
        "</soapenv:Body></soapenv:Envelope>"
    ) % (SOAP_NS, operation, escape(identity), auth_xml, escape(fmt), escape(value), operation)
    started = time.time()
    try:
        resp = open_url(ws_url.rstrip("/") + soap_path, method="POST", data=envelope.encode(),
                        headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": operation},
                        validate_certs=validate_certs, ca_path=ca_path, timeout=timeout, http_agent="ansible-voltage")
        text = resp.read().decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        raise VoltageClientError("%s SOAP failed: %s" % (op, _short(exc)))
    m = re.search(r"<(?:\w+:)?data>(.*?)</(?:\w+:)?data>", text, re.S)
    if not m:
        raise VoltageClientError("%s SOAP: no <data> in response" % op)
    return m.group(1), time.time() - started


def _short(exc):
    text = str(exc)
    body = getattr(exc, "read", None)
    if callable(body):
        try:
            detail = body().decode(errors="replace")[:160]
            fault = re.search(r"<faultstring>(.*?)</faultstring>", detail, re.S)
            text += " " + (fault.group(1) if fault else detail)
        except Exception:  # noqa: BLE001
            pass
    return text
