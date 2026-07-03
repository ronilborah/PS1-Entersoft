"""
parsers/httpx_parser.py
-----------------------
Converts raw httpx tool output into a structured signal dict.

CONTRACT
--------
Input:  dict returned by TOOL_REGISTRY["httpx"]().run(target)
        Two shapes exist depending on TOOL_MOCK_MODE:

        Mock mode  → {"tool": "httpx", "mode": "mock", "alive": True,
                       "status_code": 200, "title": "...", "webserver": "nginx",
                       "content_length": 1256, "ran_at": "..."}

        Real mode  → {"tool": "httpx", "mode": "real", "ok": True,
                       "raw": "<raw text from httpx CLI>", "ran_at": "..."}

Output: {"signal_candidates": [...], "semantic_summary": "..."}

Signal keys emitted (from onboarding appendix, Section 13):
    tech_stack_detected       — one or more web technologies identified
    server_version_disclosed  — Server header reveals a version string
    http_to_https_redirect    — target responds with HTTP → HTTPS redirect
"""

from __future__ import annotations
import re


def parse_httpx(raw: dict, target: str) -> dict:
    """Parse httpx tool output dict into signal candidates and a semantic summary.

    Works for both mock-mode structured dicts and real-mode raw text output.
    Never raises — falls back gracefully if a key is absent.
    """
    signals: list[dict] = []
    notes: list[str] = []

    mode = raw.get("mode", "real")

    if mode == "mock":
        _parse_mock(raw, target, signals, notes)
    else:
        _parse_real(raw, target, signals, notes)

    if not notes:
        notes.append("httpx returned no actionable findings.")

    return {
        "signal_candidates": signals,
        "semantic_summary": " ".join(notes),
    }


# ---------------------------------------------------------------------------
# Mock-mode parser
# ---------------------------------------------------------------------------

def _parse_mock(raw: dict, target: str, signals: list, notes: list) -> None:
    alive = raw.get("alive")
    status_code = raw.get("status_code")

    if alive is True:
        notes.append(f"Target is reachable (HTTP {status_code}).")
    else:
        notes.append("Target did not respond; may be down or filtered.")
        return  # nothing else is meaningful if it's not up

    # redirect
    if isinstance(status_code, int) and status_code in (301, 302, 307, 308):
        signals.append({
            "signal": "http_to_https_redirect",
            "evidence": f"HTTP {status_code} redirect on {target}",
            "severity": "info",
        })
        notes.append("HTTP-to-HTTPS redirect confirmed.")

    # server version disclosure
    webserver = raw.get("webserver", "")
    if webserver:
        if _has_version(webserver):
            signals.append({
                "signal": "server_version_disclosed",
                "evidence": f"Server header: {webserver}",
                "severity": "low",
            })
            notes.append(f"Server version disclosed: {webserver}.")
        else:
            notes.append(f"Web server: {webserver} (no version string).")

    # tech stack — httpx mock includes tech_stack only if the mock was extended
    tech = raw.get("tech_stack", [])
    if tech:
        signals.append({
            "signal": "tech_stack_detected",
            "evidence": f"Technologies: {', '.join(tech)}",
            "severity": "info",
        })
        notes.append(f"Tech stack: {', '.join(tech)}.")

    title = raw.get("title", "")
    if title:
        notes.append(f"Page title: \"{title}\".")


# ---------------------------------------------------------------------------
# Real-mode parser  (raw text from httpx CLI)
# ---------------------------------------------------------------------------

def _parse_real(raw: dict, target: str, signals: list, notes: list) -> None:
    if not raw.get("ok"):
        notes.append(f"httpx reported an error: {raw.get('raw', 'unknown error')}")
        return

    raw_text: str = raw.get("raw", "")
    if not raw_text:
        notes.append("httpx produced no output.")
        return

    notes.append("Target responded to httpx probe.")

    # redirect detection (httpx -follow-redirects omitted, so look for Location header)
    if re.search(r"HTTP/\d+\.?\d*\s+(301|302|307|308)", raw_text, re.IGNORECASE):
        signals.append({
            "signal": "http_to_https_redirect",
            "evidence": "Redirect status code in httpx output",
            "severity": "info",
        })
        notes.append("HTTP redirect detected.")

    # server version disclosure
    version_match = re.search(
        r"(Apache/[\d.]+|nginx/[\d.]+|PHP/[\d.]+|Microsoft-IIS/[\d.]+|"
        r"OpenSSL/[\d.]+|lighttpd/[\d.]+|Jetty/[\d.]+)",
        raw_text, re.IGNORECASE
    )
    if version_match:
        signals.append({
            "signal": "server_version_disclosed",
            "evidence": f"Version string: {version_match.group(0)}",
            "severity": "low",
        })
        notes.append(f"Server version disclosed: {version_match.group(0)}.")

    # tech stack heuristic
    tech_hits = _scan_tech(raw_text)
    if tech_hits:
        signals.append({
            "signal": "tech_stack_detected",
            "evidence": f"Technologies inferred: {', '.join(tech_hits)}",
            "severity": "info",
        })
        notes.append(f"Detected technologies: {', '.join(tech_hits)}.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _has_version(server_str: str) -> bool:
    """Return True if the server string contains a version number."""
    return bool(re.search(r"\d", server_str)) and "/" in server_str


_TECH_MARKERS = {
    "WordPress": "WordPress",
    "Drupal": "Drupal",
    "Joomla": "Joomla",
    "nginx": "nginx",
    "Apache": "Apache",
    "PHP": "PHP",
    "ASP.NET": "ASP.NET",
    "jQuery": "jQuery",
    "React": "React",
    "Bootstrap": "Bootstrap",
    "Laravel": "Laravel",
    "Django": "Django",
    "Rails": "Ruby on Rails",
}


def _scan_tech(text: str) -> list[str]:
    text_lower = text.lower()
    return [label for keyword, label in _TECH_MARKERS.items()
            if keyword.lower() in text_lower]
