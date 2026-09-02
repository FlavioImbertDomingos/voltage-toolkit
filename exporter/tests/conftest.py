"""Tests run against the real mock server, started in-process on a random port."""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

MOCK = Path(__file__).resolve().parents[2] / "mock-voltage" / "app.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def mock_server():
    """(base_http_url, base_https_url, module) for a mock Voltage running in a thread."""
    http_port, https_port = _free_port(), _free_port()
    os.environ["MOCK_KEY_HOST"] = f"127.0.0.1:{https_port}"
    os.environ["MOCK_TLS_CERT_DAYS"] = "20"
    spec = importlib.util.spec_from_file_location("mock_voltage_app", MOCK)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mock_voltage_app"] = mod
    spec.loader.exec_module(mod)
    cert, key = mod._self_signed(20, "127.0.0.1")
    threading.Thread(
        target=lambda: mod.app.run(host="127.0.0.1", port=https_port, ssl_context=(cert, key), threaded=True),
        daemon=True,
    ).start()
    threading.Thread(target=lambda: mod.app.run(host="127.0.0.1", port=http_port, threaded=True), daemon=True).start()
    import requests

    for _ in range(50):
        try:
            requests.get(f"http://127.0.0.1:{http_port}/mock/health", timeout=1)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    yield f"http://127.0.0.1:{http_port}", f"https://127.0.0.1:{https_port}", mod


@pytest.fixture
def healthy(mock_server):
    _, _, mod = mock_server
    mod._state["scenario"] = "healthy"
    yield
    mod._state["scenario"] = "healthy"


def target_for(mock_server, **overrides):
    from voltage_exporter.config import ProbeSpec, Target

    _, https, _ = mock_server
    base = dict(
        name="t",
        policy_url=f"{https}/policy/clientPolicy.xml",
        ws_url=https,
        identity="probe@demo.bank",
        secret="probe-secret",
        verify_tls=False,
        timeout=5,
        probes=[ProbeSpec("CC", "4111111111111111"), ProbeSpec("CC-ST-64O", "5500000000000004", tokenization=True)],
    )
    base.update(overrides)
    return Target(**base)
