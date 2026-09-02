"""Unit tests run the modules the way Ansible does: as a subprocess with a JSON args file.

They need `ansible-core` installed and the repository root on ANSIBLE_COLLECTIONS_PATH /
PYTHONPATH so `ansible_collections.flavioimbertdomingos.voltage` imports resolve.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

COLLECTION = Path(__file__).resolve().parents[2]
REPO_ROOT = COLLECTION.parents[2]  # contains ansible_collections/
MODULES = COLLECTION / "plugins" / "modules"


def run_module(name: str, args: dict, check_mode: bool = False, diff: bool = False) -> dict:
    payload = {"ANSIBLE_MODULE_ARGS": dict(args, _ansible_check_mode=check_mode, _ansible_diff=diff)}
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    proc = subprocess.run(
        [sys.executable, str(MODULES / f"{name}.py")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise AssertionError(f"module produced no JSON:\nstdout={proc.stdout}\nstderr={proc.stderr}")


@pytest.fixture
def state_file(tmp_path):
    return str(tmp_path / "voltage-config.yml")


# ---- the mock appliance fixture, shared with the exporter tests (loaded by path: two `tests` packages)
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("exporter_test_conftest", REPO_ROOT / "exporter" / "tests" / "conftest.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
mock_server = _mod.mock_server
