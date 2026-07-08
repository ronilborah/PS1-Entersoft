"""
tools.py
--------
Defines TOOL_REGISTRY, a dict mapping tool name -> a callable class instance
with a .run(target) method, matching the import pattern given in the
assignment:

    from tools import TOOL_REGISTRY
    result = TOOL_REGISTRY['httpx']().run(target)

Each tool supports two modes, controlled by the TOOL_MOCK_MODE env var:

- TOOL_MOCK_MODE=true  -> returns a realistic, hand-written fake result.
  No binary required. Used for local dev, demos, and CI.
- TOOL_MOCK_MODE=false -> shells out to the real binary via subprocess and
  does best-effort parsing of its output.

This file only implements the 7 tools Scout is allowed to use, plus httpx
(shared across all teams). When the real ReconAgent/Project2 repo is
available, this file can be deleted and replaced by importing the real
TOOL_REGISTRY -- main.py does not need to change, because it only relies on
the `TOOL_REGISTRY['name']().run(target)` interface.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone


def _strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', text)

def mock_mode() -> bool:
    return os.getenv("TOOL_MOCK_MODE", "true").strip().lower() == "true"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_cmd(cmd: list[str], timeout: int = 60) -> tuple[bool, str]:
    """Run a real CLI tool. Returns (ok, output_or_error)."""
    binary = cmd[0]
    if shutil.which(binary) is None:
        return False, f"binary '{binary}' not found on PATH"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = proc.stdout if proc.stdout else proc.stderr
        return True, _strip_ansi(output.strip())
    except subprocess.TimeoutExpired:
        return False, f"'{binary}' timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        return False, f"'{binary}' failed: {exc}"

class BaseTool:
    name = "base"

    def run(self, target: str) -> dict:
        if mock_mode():
            return self.mock(target)
        return self.real(target)

    def mock(self, target: str) -> dict:
        raise NotImplementedError

    def real(self, target: str) -> dict:
        raise NotImplementedError


class HttpxTool(BaseTool):
    name = "httpx"

    def mock(self, target: str) -> dict:
        return {
            "tool": "httpx",
            "target": target,
            "status_code": 200,
            "alive": True,
            "title": "Example Domain",
            "webserver": "nginx",
            "content_length": 1256,
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        ok, output = _run_cmd(
            ["httpx", "-silent", "-status-code", "-title", "-tech-detect", "-u", target]
        )
        return {"tool": "httpx", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


class Wafw00fTool(BaseTool):
    name = "wafw00f"

    def mock(self, target: str) -> dict:
        return {
            "tool": "wafw00f",
            "target": target,
            "waf_detected": True,
            "waf_name": "Cloudflare",
            "confidence": "firm",
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        ok, output = _run_cmd(["wafw00f", target])
        return {"tool": "wafw00f", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


class WhatwebTool(BaseTool):
    name = "whatweb"

    def mock(self, target: str) -> dict:
        return {
            "tool": "whatweb",
            "target": target,
            "tech_stack": ["nginx", "PHP/8.1", "WordPress 6.4", "jQuery"],
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        ok, output = _run_cmd(["whatweb", "--no-errors", target])
        return {"tool": "whatweb", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


class ShcheckTool(BaseTool):
    name = "shcheck"

    def mock(self, target: str) -> dict:
        return {
            "tool": "shcheck",
            "target": target,
            "missing_headers": ["Content-Security-Policy", "X-Frame-Options"],
            "present_headers": ["Strict-Transport-Security", "X-Content-Type-Options"],
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        # shcheck.py is typically invoked with python3 shcheck.py <url>
        ok, output = _run_cmd(["python3", "shcheck.py", target])
        if not ok:
            ok, output = _run_cmd(["shcheck", target])
        return {"tool": "shcheck", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


class TestsslTool(BaseTool):
    name = "testssl"

    def mock(self, target: str) -> dict:
        return {
            "tool": "testssl",
            "target": target,
            "tls_versions": ["TLSv1.2", "TLSv1.3"],
            "weak_protocols_found": False,
            "cert_expiry_days": 87,
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        ok, output = _run_cmd(["testssl.sh", "--fast", target], timeout=60)
        return {"tool": "testssl", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


class NmapTool(BaseTool):
    name = "nmap"

    def mock(self, target: str) -> dict:
        return {
            "tool": "nmap",
            "target": target,
            "open_ports": [
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"},
            ],
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        host = target.split("//")[-1].split("/")[0]
        ok, output = _run_cmd(["nmap", "-Pn", "-T4", "--top-ports", "100", host], timeout=120)
        return {"tool": "nmap", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


class WpscanTool(BaseTool):
    name = "wpscan"

    def mock(self, target: str) -> dict:
        return {
            "tool": "wpscan",
            "target": target,
            "is_wordpress": True,
            "wp_version": "6.4.2",
            "vulnerable_plugins": ["contact-form-7 (outdated)"],
            "ran_at": _now(),
            "mode": "mock",
        }

    def real(self, target: str) -> dict:
        ok, output = _run_cmd(["wpscan", "--url", target, "--no-banner"], timeout=180)
        return {"tool": "wpscan", "target": target, "ok": ok, "raw": output, "ran_at": _now(), "mode": "real"}


TOOL_REGISTRY = {
    "httpx": HttpxTool,
    "wafw00f": Wafw00fTool,
    "whatweb": WhatwebTool,
    "shcheck": ShcheckTool,
    "testssl": TestsslTool,
    "nmap": NmapTool,
    "wpscan": WpscanTool,
}
