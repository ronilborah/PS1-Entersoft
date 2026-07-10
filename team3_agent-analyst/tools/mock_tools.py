"""
mock_tools.py — Person B owns this file.

Fake implementations of every tool in the allowlist.
Used when TOOL_MOCK_MODE=true (default).

Every function returns a list of findings, each in the
normalized schema:
{
    "tool":        tool name string
    "type":        "Secret" | "Endpoint" | "Vulnerability" | "Info"
    "severity":    "High" | "Medium" | "Low" | "Info"
    "title":       short label
    "description": what was found
    "evidence":    the actual value / snippet (redacted if sensitive)
    "location":    where it was found (file, url, line)
}

An empty list [] means the tool ran but found nothing — that is
still a valid, successful result.
"""


def run_httpx(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "httpx",
            "type": "Info",
            "severity": "Info",
            "title": "Target Alive",
            "description": "Target is reachable and returned HTTP 200.",
            "evidence": "HTTP/1.1 200 OK",
            "location": target,
        }
    ]


def run_trufflehog(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "TruffleHog",
            "type": "Secret",
            "severity": "High",
            "title": "AWS Access Key Detected",
            "description": "A potential AWS access key was found in a JavaScript file. "
                           "AWS keys starting with AKIA are long-term credentials that "
                           "provide access to AWS resources.",
            "evidence": "AKIA****************",
            "location": f"{target}/static/js/config.bundle.js",
        }
    ]


def run_secretfinder(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "SecretFinder",
            "type": "Secret",
            "severity": "High",
            "title": "Google API Key Exposed",
            "description": "A Google API key was found hardcoded inside a JavaScript file. "
                           "Exposed API keys can be used to make unauthorized API calls "
                           "and incur costs on the owner's account.",
            "evidence": "AIza****************************",
            "location": f"{target}/assets/main.js",
        }
    ]


def run_linkfinder(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "LinkFinder",
            "type": "Endpoint",
            "severity": "Medium",
            "title": "Hidden Admin Endpoint Found",
            "description": "An internal admin endpoint was discovered inside a JavaScript file. "
                           "This endpoint is not linked anywhere in the UI but is still accessible.",
            "evidence": "/api/v1/admin/users",
            "location": f"{target}/assets/main.js",
        },
        {
            "tool": "LinkFinder",
            "type": "Endpoint",
            "severity": "Low",
            "title": "Internal API Endpoint Found",
            "description": "An API endpoint was extracted from JavaScript source code.",
            "evidence": "/api/v1/payments/export",
            "location": f"{target}/assets/main.js",
        },
    ]


def run_gitleaks(target: str, context: dict) -> list[dict]:
    # Returns empty — tool ran but found nothing
    return []


def run_git_secrets(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "git-secrets",
            "type": "Secret",
            "severity": "High",
            "title": "Hardcoded Database Password",
            "description": "A database password pattern was detected in a JavaScript file. "
                           "Hardcoded credentials expose the database to unauthorized access.",
            "evidence": "DB_PASSWORD=****",
            "location": f"{target}/static/js/app.js",
        }
    ]


def run_mapextractor(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "MapExtractor",
            "type": "Vulnerability",
            "severity": "Medium",
            "title": "JavaScript Source Map Exposed",
            "description": "A .js.map file is publicly accessible. Source maps contain the "
                           "original unminified source code, internal comments, function names, "
                           "and directory structure — giving attackers a detailed view of the codebase.",
            "evidence": f"{target}/assets/main.js.map",
            "location": f"{target}/assets/main.js.map",
        }
    ]


def run_jshole(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "JSHole",
            "type": "Vulnerability",
            "severity": "Medium",
            "title": "Outdated jQuery Detected",
            "description": "The site is using jQuery 1.12.4, which has known XSS vulnerabilities "
                           "(CVE-2020-11022, CVE-2020-11023). An attacker could potentially exploit "
                           "these to inject malicious scripts.",
            "evidence": "jquery-1.12.4.min.js",
            "location": f"{target}/static/js/jquery-1.12.4.min.js",
        }
    ]


def run_nuclei_passive(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "Nuclei (passive)",
            "type": "Vulnerability",
            "severity": "Low",
            "title": "Admin Login Panel Exposed",
            "description": "An admin login panel is publicly accessible. While not a direct "
                           "vulnerability, exposed admin panels increase attack surface and "
                           "are a common target for brute force attacks.",
            "evidence": "HTTP 200 on /admin/login",
            "location": f"{target}/admin/login",
        },
        {
            "tool": "Nuclei (passive)",
            "type": "Vulnerability",
            "severity": "Low",
            "title": "Missing Security Headers",
            "description": "The response is missing Content-Security-Policy and X-Frame-Options "
                           "headers. Missing CSP can allow XSS attacks. Missing X-Frame-Options "
                           "can allow clickjacking.",
            "evidence": "No Content-Security-Policy header in response",
            "location": target,
        },
    ]


def run_httpx_enrichment(target: str, context: dict) -> list[dict]:
    return [
        {
            "tool": "httpx (enrichment)",
            "type": "Info",
            "severity": "Info",
            "title": "HTTP Metadata Collected",
            "description": "Server fingerprint and technology stack identified from HTTP headers.",
            "evidence": "Server: nginx/1.18.0, X-Powered-By: PHP/7.4",
            "location": target,
        }
    ]


# Map tool name strings to their functions
# runner.py uses this to call the right function by name
MOCK_TOOL_MAP = {
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
