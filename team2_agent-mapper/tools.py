"""
tools.py — Mapper Agent Tool Wrappers
Each class wraps one CLI security tool installed on Kali Linux.
Every .run() method returns structured JSON — never raw terminal output.
Set TOOL_MOCK_MODE=true in .env to return fake data without real scans.
"""

import subprocess
import json
import os
import re
from urllib.parse import urlparse


# Read mock mode from environment variable
MOCK_MODE = os.getenv("TOOL_MOCK_MODE", "false").lower() == "true"
HTTPX_BINARY = os.environ.get("HTTPX_BINARY", "/usr/bin/httpx")


def extract_hostname(target: str) -> str:
    """Pulls the bare hostname from a full URL."""
    parsed = urlparse(target)
    return parsed.hostname or target


def run_command(cmd: list, timeout: int = 25) -> tuple[str, str, int]:
    """
    Runs a shell command, returns (stdout, stderr, returncode).
    Handles timeouts and crashes gracefully.
    """
    timeout = min(timeout, 45)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Tool timed out", 1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]} — is it installed?", 1
    except Exception as e:
        return "", str(e), 1


# ─────────────────────────────────────────────
# WRAPPER CLASSES
# ─────────────────────────────────────────────

class HttpxWrapper:
    """
    Confirms the target is live and grabs basic HTTP metadata.
    CLI tool: httpx (Go binary, not Python httpx)
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "live": True,
                "url": target,
                "status_code": 200,
                "title": "Mock Target",
                "server": "nginx/1.18.0",
                "content_length": 4821,
                "technologies": ["nginx", "PHP"]
            }

        host = extract_hostname(target)
        httpx_binary = os.environ.get("HTTPX_BINARY", "/usr/bin/httpx")
        stdout, stderr, code = run_command([
            httpx_binary,
            "-u", target,
            "-json",        # output as JSON
            "-silent",      # no banner
            "-title",       # grab page title
            "-tech-detect", # detect technologies
            "-status-code",
            "-content-length",
            "-web-server"
        ], timeout=25)

        if code != 0 or not stdout.strip():
            return {"live": False, "error": stderr, "url": target}

        try:
            # httpx outputs one JSON object per line — take the first
            data = json.loads(stdout.strip().splitlines()[0])
            return {
                "live": True,
                "url": data.get("url", target),
                "status_code": data.get("status-code", 0),
                "title": data.get("title", ""),
                "server": data.get("webserver", ""),
                "content_length": data.get("content-length", 0),
                "technologies": data.get("tech", [])
            }
        except json.JSONDecodeError:
            return {"live": True, "url": target, "raw": stdout[:500]}


class NaabuWrapper:
    """
    Fast port scanner.
    CLI tool: naabu
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "host": target,
                "open_ports": [80, 443, 8080, 8443],
                "total": 4
            }

        host = extract_hostname(target)
        stdout, stderr, code = run_command([
            "naabu",
            "-host", host,
            "-json",
            "-silent",
            "-top-ports", "1000"  # scan top 1000 common ports
        ], timeout=25)

        if code != 0 or not stdout.strip():
            return {"host": host, "open_ports": [], "error": stderr}

        ports = []
        for line in stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                port = entry.get("port")
                if port:
                    ports.append(port)
            except json.JSONDecodeError:
                # naabu sometimes outputs "host:port" plaintext
                if ":" in line:
                    try:
                        ports.append(int(line.strip().split(":")[-1]))
                    except ValueError:
                        pass

        return {"host": host, "open_ports": sorted(set(ports)), "total": len(ports)}


class KatanaWrapper:
    """
    Fast web crawler — finds URLs and endpoints by following links.
    CLI tool: katana
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "urls": [
                    target + "/login",
                    target + "/api/v1/users",
                    target + "/api/v1/products",
                    target + "/admin",
                    target + "/static/app.js",
                    target + "/register"
                ],
                "total": 6
            }

        stdout, stderr, code = run_command([
            "katana",
            "-u", target,
            "-json",
            "-silent",
            "-depth", "3",       # crawl 3 levels deep
            "-js-crawl",         # also crawl JS files
            "-no-scope-check"
        ], timeout=45)

        if code != 0 or not stdout.strip():
            return {"target": target, "urls": [], "error": stderr}

        urls = []
        for line in stdout.strip().splitlines():
            try:
                entry = json.loads(line)
                url = entry.get("request", {}).get("endpoint") or entry.get("url", "")
                if url:
                    urls.append(url)
            except json.JSONDecodeError:
                if line.startswith("http"):
                    urls.append(line.strip())

        return {"target": target, "urls": list(set(urls)), "total": len(urls)}


class GauWrapper:
    """
    Gets all known URLs for a domain from multiple sources
    (Wayback, OTX, Common Crawl, URLScan).
    CLI tool: gau
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "urls": [
                    target + "/old-admin",
                    target + "/backup.zip",
                    target + "/api/v2/items",
                    target + "/.env",
                    target + "/wp-login.php"
                ],
                "total": 5
            }

        host = extract_hostname(target)
        stdout, stderr, code = run_command([
            "gau",
            "--providers", "wayback,otx,commoncrawl,urlscan",
            "--subs",           # include subdomains
            host
        ], timeout=45)

        if code != 0 or not stdout.strip():
            return {"target": target, "urls": [], "error": stderr}

        urls = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"target": target, "urls": urls, "total": len(urls)}


class WaybackurlsWrapper:
    """
    Pulls historical URLs specifically from the Wayback Machine.
    CLI tool: waybackurls
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "urls": [
                    target + "/forgot-password",
                    target + "/api/v1/products",
                    target + "/internal/metrics",
                    target + "/debug"
                ],
                "total": 4
            }

        host = extract_hostname(target)
        stdout, stderr, code = run_command(
            ["waybackurls", host],
            timeout=45
        )

        if code != 0 or not stdout.strip():
            return {"target": target, "urls": [], "error": stderr}

        urls = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"target": target, "urls": urls, "total": len(urls)}


class DirsearchWrapper:
    """
    Brute-forces common directory and file paths.
    CLI tool: dirsearch
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "paths": [
                    {"path": "/admin", "status": 200},
                    {"path": "/.git", "status": 403},
                    {"path": "/config", "status": 200},
                    {"path": "/uploads", "status": 301},
                    {"path": "/.env", "status": 200}
                ],
                "total": 5
            }

        output_file = "/tmp/dirsearch_output.json"
        stdout, stderr, code = run_command([
            "dirsearch",
            "-u", target,
            "-q",                       # quiet
            "--format", "json",
            "-o", output_file,
            "--timeout", "10",
            "-t", "20"                  # 20 threads
        ], timeout=45)

        # dirsearch writes to file rather than stdout
        try:
            with open(output_file, "r") as f:
                data = json.load(f)

            results = data.get("results", [])
            paths = [
                {"path": r.get("path", ""), "status": r.get("status", 0)}
                for r in results
            ]
            return {"target": target, "paths": paths, "total": len(paths)}
        except (FileNotFoundError, json.JSONDecodeError):
            return {"target": target, "paths": [], "error": stderr or "No output file produced"}


class JsluiceWrapper:
    """
    Extracts endpoints, secrets, and API paths from JavaScript files.
    CLI tool: jsluice
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "endpoints": [
                    "/api/internal/debug",
                    "/api/v1/admin/users",
                    "/graphql"
                ],
                "secrets": [],
                "total_endpoints": 3
            }

        # jsluice needs actual JS file content to analyze
        # First grab JS URLs from the target, then run jsluice on each
        stdout, stderr, code = run_command([
            "katana",
            "-u", target,
            "-silent",
            "-extension-match", "js"    # only JS files
        ], timeout=45)

        js_urls = [line.strip() for line in stdout.splitlines() if line.strip().endswith(".js")]

        if not js_urls:
            return {"target": target, "endpoints": [], "secrets": [], "note": "No JS files found"}

        all_endpoints = []
        all_secrets = []

        for js_url in js_urls[:10]:     # cap at 10 JS files to avoid timeout
            js_stdout, _, js_code = run_command(
                ["jsluice", "urls", js_url],
                timeout=25
            )
            for line in js_stdout.splitlines():
                try:
                    entry = json.loads(line)
                    url = entry.get("url", "")
                    kind = entry.get("kind", "")
                    if "secret" in kind.lower():
                        all_secrets.append(entry)
                    elif url:
                        all_endpoints.append(url)
                except json.JSONDecodeError:
                    pass

        return {
            "target": target,
            "endpoints": list(set(all_endpoints)),
            "secrets": all_secrets,
            "total_endpoints": len(set(all_endpoints))
        }


class NirjasWrapper:
    """
    Extracts comments from source code files — often leaks info.
    CLI tool: nirjas
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "comments": [
                    "TODO: remove hardcoded API key",
                    "dev endpoint: /api/test — do not ship",
                    "Author: dev@company.com"
                ],
                "total": 3
            }

        stdout, stderr, code = run_command([
            "nirjas",
            "-u", target
        ], timeout=25)

        if code != 0 or not stdout.strip():
            return {"target": target, "comments": [], "error": stderr}

        try:
            data = json.loads(stdout)
            comments = data.get("single_line_comment", []) + data.get("multi_line_comment", [])
            return {"target": target, "comments": comments, "total": len(comments)}
        except json.JSONDecodeError:
            # fallback: return raw lines as comments
            comments = [line.strip() for line in stdout.splitlines() if line.strip()]
            return {"target": target, "comments": comments, "total": len(comments)}


class SourceMapsWrapper:
    """
    Looks for .map files that can expose full original source code.
    CLI tool: source_maps_downloader (or manual detection via httpx)
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "target": target,
                "map_files_found": [
                    target + "/static/app.js.map",
                    target + "/static/vendor.js.map"
                ],
                "total": 2
            }

        # First find JS files via katana, then probe for .map equivalents
        stdout, stderr, code = run_command([
            "katana",
            "-u", target,
            "-silent",
            "-extension-match", "js"
        ], timeout=45)

        js_urls = [line.strip() for line in stdout.splitlines() if ".js" in line]
        map_urls = [url + ".map" for url in js_urls]

        found_maps = []
        for map_url in map_urls[:10]:
            probe_stdout, _, probe_code = run_command([
                "httpx",
                "-u", map_url,
                "-silent",
                "-status-code",
                "-mc", "200"    # only report 200 OK
            ], timeout=25)
            if probe_stdout.strip():
                found_maps.append(map_url)

        return {
            "target": target,
            "map_files_found": found_maps,
            "total": len(found_maps)
        }


class NmapServiceWrapper:
    """
    Service and version detection on open ports.
    CLI tool: nmap
    """
    def run(self, target: str) -> dict:
        if MOCK_MODE:
            return {
                "host": target,
                "services": {
                    "80":   {"service": "http",  "product": "nginx",  "version": "1.18.0"},
                    "443":  {"service": "https", "product": "nginx",  "version": "1.18.0"},
                    "8080": {"service": "http",  "product": "Jetty",  "version": "9.4.43"}
                }
            }

        host = extract_hostname(target)
        output_file = "/tmp/nmap_output.json"

        nmap_cmd = [
            "nmap",
            "-sV",                  # service/version detection
            "--top-ports", "100",   # top 100 ports (faster than full scan)
            "-T4",                  # aggressive timing
            "-oX", output_file,     # XML output (correct nmap flag; -oJ is not standard)
            host,                   # scan target
        ]
        print(f"Running nmap command: {' '.join(nmap_cmd)}")
        stdout, stderr, code = run_command(nmap_cmd, timeout=25)

        try:
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                return {"services": {}, "error": "nmap produced no output"}
            with open(output_file, "r") as f:
                output_content = f.read()
        except FileNotFoundError:
            return {"services": {}, "error": "nmap produced no output"}
        if not output_content:
            return {"services": {}, "error": "nmap produced no output"}
        print(f"nmap output first 200 chars: {output_content[:200]!r}")

        try:
            data = json.loads(output_content)

            services = {}
            hosts = data.get("nmaprun", {}).get("host", [])
            if isinstance(hosts, dict):
                hosts = [hosts]

            for h in hosts:
                ports = h.get("ports", {}).get("port", [])
                if isinstance(ports, dict):
                    ports = [ports]
                for p in ports:
                    port_id = p.get("@portid", "")
                    state = p.get("state", {}).get("@state", "")
                    if state == "open":
                        svc = p.get("service", {})
                        services[port_id] = {
                            "service": svc.get("@name", ""),
                            "product": svc.get("@product", ""),
                            "version": svc.get("@version", "")
                        }

            return {"host": host, "services": services}
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            return {"host": host, "services": {}, "error": stderr or "Failed to parse nmap output"}


# ─────────────────────────────────────────────
# TOOL REGISTRY
# Maps tool names to their wrapper classes.
# This is the only thing main.py imports.
# ─────────────────────────────────────────────

TOOL_REGISTRY = {
    "httpx":                    HttpxWrapper,
    "naabu":                    NaabuWrapper,
    "katana":                   KatanaWrapper,
    "gau":                      GauWrapper,
    "waybackurls":              WaybackurlsWrapper,
    "dirsearch":                DirsearchWrapper,
    "jsluice":                  JsluiceWrapper,
    "nirjas":                   NirjasWrapper,
    "source_maps_downloader":   SourceMapsWrapper,
    "nmap_service":             NmapServiceWrapper,
}
