"""
runner.py — Person B owns this file.

Executes the selected tools and collects all their findings.

Picks between mock mode (TOOL_MOCK_MODE=true, default) and
real mode (TOOL_MOCK_MODE=false, needs Kali binaries installed).

Each tool is called for every surface item (JS file or endpoint)
that came from the Mapper context. If no surface was passed:
  - JS_ONLY_TOOLS (secretfinder, linkfinder, jshole, mapextractor)
    try a lightweight HTML-scraping fallback to auto-discover real
    <script src="..."> files on the target. If none are found, they
    skip entirely (they cannot produce meaningful results on non-JS
    content).
  - JS_PREFERRED_TOOLS (trufflehog, gitleaks, git_secrets) also try
    the same auto-discovery fallback first, since they benefit from
    scanning real JS files — but if discovery finds nothing, they
    still fall back to scanning the raw target URL, since they scan
    generic file/text content and can still produce meaningful
    results against a homepage.
  - All other tools (httpx, httpx_enrichment, nuclei_passive) fall
    back to the raw target URL as before, since they don't require
    JS input at all.

A single tool failure never crashes the whole request — the error
is logged and that tool returns [] for that item.
"""

import logging
import os
import json
import re
import urllib.request

from tools.mock_tools import MOCK_TOOL_MAP
from tools.wrappers import REAL_TOOL_MAP

logger = logging.getLogger("agent-analyst.runner")

MOCK_MODE = os.getenv("TOOL_MOCK_MODE", "true").lower() == "true"

ALLOWED_TOOLS = [
    "httpx", "trufflehog", "secretfinder", "linkfinder",
    "gitleaks", "git_secrets", "mapextractor", "jshole",
    "nuclei_passive", "httpx_enrichment",
]

# Tools that only produce meaningful results against actual JS files.
# If Mapper found no js_files, we try a lightweight HTML-scrape fallback
# (_discover_js_from_html) to find real JS before falling back to skip.
JS_ONLY_TOOLS = {"secretfinder", "linkfinder", "jshole", "mapextractor"}

# Tools that scan generic file/text content for secrets. They benefit from
# real JS files when auto-discovery finds them (more meaningful surface
# than scanning raw homepage HTML), but — unlike JS_ONLY_TOOLS — they can
# still produce legitimate results against the bare target HTML, so they
# fall back to [target] rather than skipping if no JS is discovered.
JS_PREFERRED_TOOLS = {"trufflehog", "gitleaks", "git_secrets"}

_JS_DISCOVERY_TIMEOUT = 15  # seconds


def _get_tool_fn(tool_name: str):
    """Return the right function for the tool based on mock/real mode."""
    tool_map = MOCK_TOOL_MAP if MOCK_MODE else REAL_TOOL_MAP
    return tool_map.get(tool_name)


def _discover_js_from_html(target: str) -> list[str]:
    """
    Fallback JS discovery when Mapper context provides no js_files.

    Fetches the target's homepage HTML and scrapes <script src="..."> tags
    to find real, live JS files the site is actually serving. This is NOT
    synthetic/fake data — every URL returned here is a real script tag
    found on the page. It exists so JS-dependent tools can be exercised
    and tested even when the full Mapper pipeline hasn't run yet, without
    silently scanning HTML pretending it's JS.

    Note: this only scrapes the single homepage HTML response and only
    finds JS referenced via a static <script src="..."> tag. It will NOT
    find JS that's loaded dynamically (e.g. via document.write, DOM
    injection), referenced only on other pages, or embedded inline
    without a src attribute. Real Mapper output, which crawls multiple
    pages and can execute JS, will generally find more than this
    fallback can. This is a lightweight stand-in, not a replacement.

    Returns [] on any failure (network error, no script tags found, etc.)
    — never raises, so a bad target can't crash the caller.
    """
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "ReconAgent/1.0"})
        with urllib.request.urlopen(req, timeout=_JS_DISCOVERY_TIMEOUT) as resp:
            html = resp.read().decode(errors="ignore")
    except Exception as e:
        logger.warning("JS auto-discovery failed to fetch %s: %s", target, e)
        return []

    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    js_files = []
    for src in srcs:
        if src.startswith("http://") or src.startswith("https://"):
            js_files.append(src)
        elif src.startswith("//"):
            # protocol-relative URL, e.g. //cdn.example.com/lib.js
            js_files.append("https:" + src)
        else:
            # relative path, e.g. /static/app.js or static/app.js
            js_files.append(target.rstrip("/") + "/" + src.lstrip("/"))

    if js_files:
        logger.info(
            "JS auto-discovery found %d script(s) on %s: %s",
            len(js_files), target, js_files,
        )
    else:
        logger.info("JS auto-discovery found no <script src> tags on %s", target)

    return js_files


def _build_surface(
    target: str,
    context_data: dict,
    js_only: bool = False,
    js_preferred: bool = False,
) -> list[str]:
    """
    Build the list of URLs/files to analyze.

    Prefers what Mapper discovered. If nothing was passed:
      - JS-only tools try the HTML-scrape fallback; if that finds
        nothing either, they get an empty surface (caller skips).
      - JS-preferred tools try the HTML-scrape fallback too, but fall
        back to scanning the raw target URL if discovery finds nothing.
      - All other tools fall back to scanning the raw target URL,
        same as before.
    """
    surface = []
    surface.extend(context_data.get("js_files", []))
    surface.extend(context_data.get("urls", []))

    # endpoints are paths like /api/users — prefix with target
    for ep in context_data.get("endpoints", []):
        if ep.startswith("http"):
            surface.append(ep)
        else:
            surface.append(target.rstrip("/") + ep)

    if not surface:
        if js_only:
            surface = _discover_js_from_html(target)
        elif js_preferred:
            discovered = _discover_js_from_html(target)
            surface = discovered if discovered else [target]
        else:
            surface = [target]

    return surface


def run_tool(tool_name: str, target: str, context_data: dict) -> list[dict]:
    """
    Run a single tool across the available surface.
    """
    logger.info("TOOL_MOCK_MODE=%s", MOCK_MODE)

    if tool_name not in ALLOWED_TOOLS:
        logger.warning("Blocked tool not in allowlist: %s", tool_name)
        return []

    fn = _get_tool_fn(tool_name)
    if fn is None:
        logger.warning("No implementation found for tool: %s", tool_name)
        return []

    js_only = tool_name in JS_ONLY_TOOLS
    js_preferred = tool_name in JS_PREFERRED_TOOLS
    surface = _build_surface(target, context_data, js_only=js_only, js_preferred=js_preferred)

    if not surface:
        logger.info(
            "%s skipped — no js_files from Mapper context and no <script src> "
            "tags discovered on %s",
            tool_name, target,
        )
        return []

    findings = []
    for item in surface:
        try:
            results = fn(item, context_data)
            if results:
                findings.extend(results)
        except Exception as e:
            logger.error("%s failed on %s: %s", tool_name, item, e)

    logger.info(
        "%s produced %d finding(s):\n",
        tool_name,
        len(findings),
    )
    return findings


def run_tools(tool_names: list[str], target: str, context_data: dict) -> list[dict]:
    all_findings = []
    for tool in tool_names:
        all_findings.extend(
            run_tool(tool, target, context_data)
        )
    return all_findings
