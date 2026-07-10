"""
wrappers.py — Person B owns this file.

Real tool execution — shells out to actual installed binaries on Kali.
Only called when TOOL_MOCK_MODE=false.

Each function takes (target, context) and returns a list of findings
in the SAME normalized schema as mock_tools.py.

If a binary isn't installed, the function catches the error and
returns [] instead of crashing the whole request.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import urllib.request
from urllib.parse import urlparse

# Add this near the top of wrappers.py right after your imports:
EXTERNAL_DIR = os.getenv("EXTERNAL_TOOLS_DIR", "./external")
# Force the system path to look inside your external directory first
os.environ["PATH"] = os.path.abspath(EXTERNAL_DIR) + os.path.pathsep + os.environ.get("PATH", "")

# Nuclei templates dir — explicit and overridable per-machine, so teammates
# don't hit the "no templates provided for scan" error nuclei throws when
# its own default config path doesn't have templates cloned yet.
NUCLEI_TEMPLATES_DIR = os.getenv("NUCLEI_TEMPLATES_DIR", os.path.expanduser("./nuclei-templates"))
HTTPX_BINARY = os.getenv(
    "HTTPX_BINARY",
    "/home/kali/go/bin/httpx",
)

logger = logging.getLogger("agent-analyst.wrappers")

TIMEOUT = 60  # seconds per tool call


def _run_cmd(cmd: list[str], timeout: int = TIMEOUT) -> subprocess.CompletedProcess:
    """Run a shell command and return the result. Never raises on bad exit code."""
    logger.info("Running: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _download(url: str) -> str | None:
    """Download a URL to a temp file. Returns the temp file path or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconAgent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content_type = resp.headers.get("Content-Type", "").lower()
            data = resp.read()
            logger.info(
                "Downloaded %s (%d bytes, %s)",
                url,
                len(data),
                content_type,
                )
            if (
                "javascript" not in content_type
                and "json" not in content_type
                and "text" not in content_type
                ):
                logger.warning(
                    "Unexpected content type %s for %s",
                    content_type,
                    url,
                    )
        fd, path = tempfile.mkstemp(suffix=".js")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return path
    except Exception as e:
        logger.warning("Download failed for %s: %s", url, e)
        return None


def run_httpx(target: str, context: dict) -> list[dict]:
    if not os.path.exists(HTTPX_BINARY):
        logger.warning("ProjectDiscovery httpx not found at %s", HTTPX_BINARY)
        return []
    proc = _run_cmd([
        HTTPX_BINARY,
        "-u",
        target,
        "-silent",
        "-json",
        "-status-code",
    ])
    logger.info("httpx binary: %s", shutil.which("httpx"))
    logger.info("httpx return code: %s", proc.returncode)
    logger.info("httpx stdout:\n%s", proc.stdout)
    logger.info("httpx stderr:\n%s", proc.stderr)
    if proc.returncode != 0 and proc.stderr.strip():
        logger.warning("httpx error for %s: %s", target, proc.stderr.strip()[:200])
    findings = []
    for line in proc.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            findings.append({
                "tool": "httpx",
                "type": "Info",
                "severity": "Info",
                "title": "Target Alive",
                "description": f"Target responded with HTTP {obj.get('status_code')}.",
                "evidence": f"HTTP {obj.get('status_code')}",
                "location": obj.get("url", target),
            })
        except json.JSONDecodeError:
            continue
    return findings


def run_trufflehog(target: str, context: dict) -> list[dict]:
    if not shutil.which("trufflehog"):
        logger.warning("trufflehog not found")
        return []
    local = _download(target) if target.startswith("http") else target
    if not local:
        return []
    try:
        proc = _run_cmd(["trufflehog", "filesystem", local, "--json", "--no-update"], timeout=90)
        if proc.returncode != 0:
            logger.warning(
                "Trufflehog failed for %s (exit %d)\n%s",
                target,
                proc.returncode,
                proc.stderr.strip(),
                )
            return []
        findings = []
        for line in proc.stdout.strip().splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "tool": "TruffleHog",
                    "type": "Secret",
                    "severity": "High",
                    "title": f"{obj.get('DetectorName', 'Secret')} Detected",
                    "description": f"A secret matching the {obj.get('DetectorName')} pattern was found.",
                    "evidence": obj.get("Redacted", "REDACTED"),
                    "location": local,
                })
            except json.JSONDecodeError:
                continue
        return findings
    finally:
        if local != target and os.path.exists(local):
            os.unlink(local)


def run_secretfinder(target: str, context: dict) -> list[dict]:
    script = os.path.join(EXTERNAL_DIR, "SecretFinder", "SecretFinder.py")
    if not os.path.exists(script):
        logger.warning("SecretFinder not found at %s", script)
        return []
    
    # FIX: Download the web script content locally before scanning it
    local = _download(target) if target.startswith("http") else target
    if not local:
        return []
        
    try:
        proc = _run_cmd(["python3", script, "-i", local, "-o", "cli"])
        if proc.returncode != 0:
            logger.warning(
                "SecretFinder failed for %s (exit %d)\n%s",
                target,
                proc.returncode,
                proc.stderr.strip(),
                )
            return []
        findings = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                findings.append({
                    "tool": "SecretFinder",
                    "type": "Secret",
                    "severity": "High",
                    "title": "Potential Secret in JS",
                    "description": "SecretFinder matched a secret pattern in the JavaScript file.",
                    "evidence": line[:80],
                    "location": target,
                })
        return findings
    finally:
        # Clean up the temporary downloaded script from disk
        if local != target and os.path.exists(local):
            os.unlink(local)


def run_linkfinder(target: str, context: dict) -> list[dict]:
    script = os.path.join(EXTERNAL_DIR, "LinkFinder", "linkfinder.py")
    if not os.path.exists(script):
        logger.warning("LinkFinder not found at %s", script)
        return []
        
    # FIX: If it's a web target, download the target file/script locally first 
    local = _download(target) if target.startswith("http") else target
    if not local:
        return []

    proc = _run_cmd(["python3", script, "-i", local, "-o", "cli"])
    if proc.returncode != 0:
            logger.warning(
                "LinkFinder failed for %s (exit %d)\n%s",
                target,
                proc.returncode,
                proc.stderr.strip(),
                )
            return []
    findings = []
    
    try:
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(("[!]", "[+]", "[INFO]", "[WARNING]")):
                continue
            findings.append({
                "tool": "LinkFinder",
                "type": "Endpoint",
                "severity": "Low",
                "title": "Endpoint Discovered",
                "description": "An endpoint was extracted from JavaScript source code.",
                "evidence": line,
                "location": target,
            })
        return findings
    finally:
        if local != target and os.path.exists(local):
            os.unlink(local)


def run_gitleaks(target: str, context: dict) -> list[dict]:
    if not shutil.which("gitleaks"):
        logger.warning("gitleaks not found")
        return []
    logger.info("Using gitleaks: %s", shutil.which("gitleaks"))
    local = _download(target) if target.startswith("http") else target
    if not local:
        return []
    tmp_dir = tempfile.mkdtemp()
    try:
        import shutil as sh
        sh.copy(local, os.path.join(tmp_dir, "file.js"))
        report = os.path.join(tmp_dir, "report.json")
        proc=_run_cmd(["gitleaks", "detect", "--source", tmp_dir, "--no-git",
                  "--report-format", "json", "--report-path", report], timeout=90)
        if proc.returncode != 0:
            logger.warning(
                "gitleaks failed for %s (exit %d)\n%s",
                target,
                proc.returncode,
                proc.stderr.strip(),
                )
            return []
        findings = []
        if os.path.exists(report):
            with open(report) as f:
                for item in json.load(f):
                    findings.append({
                        "tool": "Gitleaks",
                        "type": "Secret",
                        "severity": "High",
                        "title": f"Secret: {item.get('RuleID', 'unknown')}",
                        "description": f"Gitleaks rule '{item.get('RuleID')}' matched.",
                        "evidence": item.get("Match", "")[:60],
                        "location": target,
                    })
        else:
            logger.warning("Gitleaks completed but produced no report for %s",
                           target,
                           )
        return findings
    finally:
        import shutil as sh
        sh.rmtree(tmp_dir, ignore_errors=True)
        if local != target and os.path.exists(local):
            os.unlink(local)


def run_git_secrets(target: str, context: dict) -> list[dict]:
    # git-secrets needs a git repo — minimal support for web targets
    if not shutil.which("git-secrets"):
        logger.warning("git-secrets not found")
        return []
    logger.info("Using git-secrets: %s", shutil.which("git-secrets"))
    local = _download(target) if target.startswith("http") else target
    if not local:
        return []
    proc = _run_cmd(["git-secrets", "--scan", local])
    if proc.returncode not in (0, 1):
        logger.warning(
            "git-secrets failed for %s (exit %d)\n%s",
            target,
            proc.returncode,
            proc.stderr.strip(),
            )
        return []
    logger.info(
    "git-secrets stdout lines: %d, stderr lines: %d",
    len(proc.stdout.splitlines()),
    len(proc.stderr.splitlines()),
    )
    findings = []
    for line in (proc.stdout + proc.stderr).splitlines():
        if line.strip():
            findings.append({
                "tool": "git-secrets",
                "type": "Secret",
                "severity": "High",
                "title": "Credential Pattern Matched",
                "description": "git-secrets detected a credential pattern.",
                "evidence": line.strip()[:80],
                "location": target,
            })
    if local != target and os.path.exists(local):
        os.unlink(local)
    return findings


def run_mapextractor(target: str, context: dict) -> list[dict]:
    """Check if a .js.map file exists alongside a JS file."""
    if not urlparse(target).path.endswith(".js"):
        return []
    map_url = target + ".map"
    try:
        req = urllib.request.Request(map_url, headers={"User-Agent": "ReconAgent/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                return []
            data = json.loads(resp.read())
        sources = data.get("sources", [])
        findings = [{
            "tool": "MapExtractor",
            "type": "Vulnerability",
            "severity": "Medium",
            "title": "Source Map Exposed",
            "description": f"A .js.map file is publicly accessible, revealing "
                           f"{len(sources)} original source file(s).",
            "evidence": map_url,
            "location": map_url,
        }]
        for src in sources[:5]:
            findings.append({
                "tool": "MapExtractor",
                "type": "Info",
                "severity": "Info",
                "title": "Source File Revealed",
                "description": "Original source file path exposed via source map.",
                "evidence": src,
                "location": map_url,
            })
        return findings
    except Exception as e:
        logger.warning("mapextractor: no source map found for %s (%s)", target, e)
        return []


def run_jshole(target: str, context: dict) -> list[dict]:
    """Detect known-vulnerable JS libraries by version string."""
    import re
    local = _download(target) if target.startswith("http") else target
    if not local:
        return []
    try:
        with open(local, "r", errors="ignore") as f:
            content = f.read(200_000)
        logger.info(
        "JSHole scanning %s (%d bytes)",
        target,
        len(content),
        )
        findings = []
        # jQuery version check
        match = re.search(r"jQuery\s+v?([\d.]+)|jquery[.-]?([\d.]+)(?:\.min)?\.js",
                          content,
                          re.I,)
        if match:
            version = next(g for g in match.groups() if g)
            logger.info("Detected jQuery version: %s", version)
            known_vulns = {
                "1.12.4": ["CVE-2020-11022", "CVE-2020-11023"],
                "1.11.3": ["CVE-2015-9251"],
                "2.2.4":  ["CVE-2019-11358"],
            }
            vulns = known_vulns.get(version, [])
            severity = "Medium" if vulns else "Info"
            findings.append({
                "tool": "JSHole",
                "type": "Vulnerability",
                "severity": severity,
                "title": f"jQuery {version} Detected",
                "description": f"jQuery {version} found. Known CVEs: {', '.join(vulns) if vulns else 'none in database'}.",
                "evidence": f"jquery {version}",
                "location": target,
            })
        if not match:
            logger.info("No supported JS library version detected")
        return findings
    finally:
        if local != target and os.path.exists(local):
            os.unlink(local)


def run_nuclei_passive(target: str, context: dict) -> list[dict]:
    if not shutil.which("nuclei"):
        logger.warning("nuclei not found")
        return []
    
    if not os.path.isdir(NUCLEI_TEMPLATES_DIR):
        logger.warning(
            "nuclei templates directory not found at %s — skipping. "
            "Clone https://github.com/projectdiscovery/nuclei-templates.git "
            "or set NUCLEI_TEMPLATES_DIR.",
            NUCLEI_TEMPLATES_DIR,
        )
        return []
    proc = _run_cmd([
        "nuclei", "-u", target,
        "-t", NUCLEI_TEMPLATES_DIR,
        "-tags", "exposure,config,panel,headers",
         "-silent", "-jsonl",
    ], timeout=240)
    if proc.returncode != 0 and proc.stderr.strip():
        logger.warning("nuclei error for %s: %s", target, proc.stderr.strip()[:200])
    findings = []
    for line in proc.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            findings.append({
                "tool": "Nuclei (passive)",
                "type": "Vulnerability",
                "severity": obj.get("info", {}).get("severity", "info").capitalize(),
                "title": obj.get("info", {}).get("name", "Nuclei Finding"),
                "description": obj.get("info", {}).get("description", ""),
                "evidence": obj.get("matched-at", ""),
                "location": obj.get("matched-at", target),
            })
        except json.JSONDecodeError:
            continue
    return findings


def run_httpx_enrichment(target: str, context: dict) -> list[dict]:
    if not os.path.exists(HTTPX_BINARY):
        logger.warning(
        "ProjectDiscovery httpx not found at %s",
        HTTPX_BINARY,
        )
        return []

    proc = _run_cmd([
        HTTPX_BINARY, "-u", target, "-silent", "-json",
        "-status-code", "-content-type", "-server", "-tech-detect",
    ])
    if proc.returncode != 0 and proc.stderr.strip():
        logger.warning("httpx enrichment error for %s: %s", target, proc.stderr.strip()[:200])
    findings = []
    for line in proc.stdout.strip().splitlines():
        try:
            obj = json.loads(line)
            findings.append({
                "tool": "httpx (enrichment)",
                "type": "Info",
                "severity": "Info",
                "title": "HTTP Metadata",
                "description": "HTTP response metadata collected.",
                "evidence": (f"Status: {obj.get('status_code')} | "
                             f"Server: {obj.get('webserver', 'unknown')} | "
                             f"Tech: {', '.join(obj.get('tech', []))}"),
                "location": obj.get("url", target),
            })
        except json.JSONDecodeError:
            continue
    return findings


# Map used by runner.py to call real tools by name
REAL_TOOL_MAP = {
    "httpx":            run_httpx,
    "trufflehog":       run_trufflehog,
    "secretfinder":     run_secretfinder,
    "linkfinder":       run_linkfinder,
    "gitleaks":         run_gitleaks,
    "git_secrets":      run_git_secrets,
    "mapextractor":     run_mapextractor,
    "jshole":           run_jshole,
    "nuclei_passive":   run_nuclei_passive,
    "httpx_enrichment": run_httpx_enrichment,
}
