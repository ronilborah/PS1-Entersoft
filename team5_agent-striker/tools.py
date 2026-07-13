"""tools.py — Tool registry for agent-striker.

Set TOOL_MOCK_MODE=true in .env (or environment) to run without real binaries.
Mock outputs are realistic representations of what each tool actually returns.
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlsplit, parse_qsl, urlencode

from dotenv import load_dotenv
load_dotenv()

MOCK_MODE: bool = os.getenv("TOOL_MOCK_MODE", "true").lower() == "true"

TOOLS_DIR = os.path.expanduser(os.getenv("TOOLS_DIR", "~/tools"))


def _script_path(folder: str, script: str) -> str:
    return os.path.join(TOOLS_DIR, folder, script)


def _strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


# ── Base class ────────────────────────────────────────────────────────────────

class BaseTool:
    name: str = ""
    def run(self, target: str, **kwargs) -> str:
        raise NotImplementedError


# ── httpx ─────────────────────────────────────────────────────────────────────

class HttpxTool(BaseTool):
    name = "httpx"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "url": target, "status_code": 200,
                "title": "Demo App", "technologies": ["React", "Node.js"],
                "server": "nginx/1.18.0", "waf": None,
                "response_headers": {"X-Frame-Options": "SAMEORIGIN"}
            })
        if shutil.which("httpx-toolkit") is None:
            raise RuntimeError("httpx-toolkit: not available in this environment — binary missing or incompatible")
        result = subprocess.run(
            ["httpx-toolkit", "-u", target, "-json", "-tech-detect", "-title", "-status-code"],
            capture_output=True, text=True, timeout=60
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── sqlmap ────────────────────────────────────────────────────────────────────

class SqlmapTool(BaseTool):
    name = "sqlmap"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "injectable_params": ["id", "user_id"],
                "technique": "UNION-based",
                "dbms": "MySQL 8.0",
                "confirmed": True,
                "risk_level": "HIGH",
                "payload": "1 UNION SELECT NULL,NULL,version()--"
            })
        if shutil.which("sqlmap") is None:
            raise RuntimeError("sqlmap: not available in this environment — binary missing or incompatible")
        param = kwargs.get("param", "")
        args = ["sqlmap", "-u", target, "--batch", "--level=3", "--risk=2"]
        if param:
            args.append(f"--data={param}")
        result = subprocess.run(
            args,
            capture_output=True, text=True, timeout=240
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── xsstrike ──────────────────────────────────────────────────────────────────

class XsstrikeTool(BaseTool):
    name = "xsstrike"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "vulnerable_params": ["q", "search"],
                "payload": "<script>alert(document.cookie)</script>",
                "reflected": True,
                "context": "HTML attribute",
                "confidence": 0.92
            })
        script = _script_path("XSStrike", "xsstrike.py")
        if not os.path.exists(script):
            raise RuntimeError("xsstrike: not available in this environment — binary missing or incompatible")
        result = subprocess.run(
            ["python3", script, "-u", target, "--skip-dom"],
            capture_output=True, text=True, timeout=120
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── dalfox ────────────────────────────────────────────────────────────────────

class DalfoxTool(BaseTool):
    name = "dalfox"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "findings": [
                    {
                        "param": "returnUrl",
                        "payload": "\"><img src=x onerror=alert(1)>",
                        "type": "reflected_xss",
                        "severity": "HIGH",
                        "confirmed": True
                    }
                ]
            })
        if shutil.which("dalfox") is None:
            raise RuntimeError("dalfox: not available in this environment — binary missing or incompatible")
        result = subprocess.run(
            ["dalfox", "url", target],
            capture_output=True, text=True, timeout=120
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── smuggler ──────────────────────────────────────────────────────────────────

class SmugglerTool(BaseTool):
    name = "smuggler"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "vulnerable": True,
                "technique": "CL.TE",
                "evidence": "Timeout differential detected on malformed chunked request",
                "backend_server": "gunicorn/20.1.0",
                "risk": "CRITICAL"
            })
        script = _script_path("smuggler", "smuggler.py")
        if not os.path.exists(script):
            raise RuntimeError("smuggler: not available in this environment — binary missing or incompatible")
        result = subprocess.run(
            ["python3", script, "-u", target],
            capture_output=True, text=True, timeout=120
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── ssrfmap ───────────────────────────────────────────────────────────────────

class SsrfmapTool(BaseTool):
    name = "ssrfmap"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "ssrf_found": True,
                "param": "url",
                "internal_host_reached": "169.254.169.254",
                "cloud_metadata_exposed": True,
                "evidence": "AWS IMDSv1 metadata returned via url= parameter"
            })
        script = _script_path("SSRFmap", "ssrfmap.py")
        if not os.path.exists(script):
            raise RuntimeError("ssrfmap: not available in this environment — binary missing or incompatible")
        param = kwargs.get("param")
        parts = urlsplit(target)
        query_pairs = parse_qsl(parts.query)
        if not param:
            param = query_pairs[0][0] if query_pairs else "url"
        if not any(k == param for k, _ in query_pairs):
            query_pairs.append((param, "CHANGEME"))
        new_query = urlencode(query_pairs)
        path = parts.path or "/"
        request_line = f"GET {path}?{new_query} HTTP/1.1" if new_query else f"GET {path} HTTP/1.1"
        raw_request = (
            f"{request_line}\r\n"
            f"Host: {parts.netloc}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        try:
            tmp.write(raw_request)
            tmp.close()
            result = subprocess.run(
                ["python3", script, "-r", tmp.name, "-p", param, "-m", "readfiles,portscan"],
                capture_output=True, text=True, timeout=120
            )
            return _strip_ansi(result.stdout or result.stderr)
        finally:
            os.unlink(tmp.name)


# ── tplmap ────────────────────────────────────────────────────────────────────

class TplmapTool(BaseTool):
    # Runs SSTImap under the hood — a maintained Python 3 rewrite of the
    # unmaintained tplmap — while keeping this class/registry key as "tplmap"
    # for API stability.
    name = "tplmap"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "ssti_found": True,
                "engine": "Jinja2",
                "param": "template",
                "rce_possible": True,
                "test_payload": "{{7*7}}",
                "response": "49"
            })
        script = _script_path("SSTImap", "sstimap.py")
        if not os.path.exists(script):
            raise RuntimeError("tplmap: not available in this environment — binary missing or incompatible")
        result = subprocess.run(
            ["python3", script, "-u", target, "-s"],
            capture_output=True, text=True, timeout=120
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── crlfuzzer ─────────────────────────────────────────────────────────────────

class CrlfuzzerTool(BaseTool):
    # Runs crlfuzz binary — the real actively-maintained tool for this job.
    # Registry key stays "crlfuzzer" for API stability.
    name = "crlfuzzer"

    def run(self, target: str, **kwargs) -> str:
        if MOCK_MODE:
            return json.dumps({
                "target": target,
                "crlf_found": True,
                "param": "redirect",
                "injected_header": "X-Injected: crlf-test",
                "payload": "%0d%0aX-Injected:%20crlf-test",
                "severity": "MEDIUM"
            })
        if shutil.which("crlfuzz") is None:
            raise RuntimeError("crlfuzzer: not available in this environment — binary missing or incompatible")
        result = subprocess.run(
            ["crlfuzz", "-u", target],
            capture_output=True, text=True, timeout=60
        )
        return _strip_ansi(result.stdout or result.stderr)


# ── Registry ──────────────────────────────────────────────────────────────────

TOOL_REGISTRY: dict[str, type[BaseTool]] = {
    "httpx":     HttpxTool,
    "sqlmap":    SqlmapTool,
    "xsstrike":  XsstrikeTool,
    "dalfox":    DalfoxTool,
    "smuggler":  SmugglerTool,
    "ssrfmap":   SsrfmapTool,
    "tplmap":    TplmapTool,
    "crlfuzzer": CrlfuzzerTool,
}
