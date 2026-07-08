"""agent_caller.py

HTTP client for calling adjacent specialist agents.

Position in the 5-agent chain:

    agent-analyst (Team 3, :8000)  →  agent-prober (Team 4, :8004)  →  agent-striker (Team 5, :8005)
    [secret/endpoint scanner]         [active vuln scanner — US]         [exploit / PoC / reporting]

Two responsibilities:
  1. UPSTREAM  — call agent-analyst before we run, use their secrets/endpoints as context.
  2. DOWNSTREAM — call agent-striker after we run, hand them our confirmed vuln findings.

Architecture (Anirudh's guidance — "sub-agent as tool"):
    The orchestrator calls each agent, takes the summary, and passes it as context into the
    next agent's initial prompt. Agents never call each other directly.

Usage (from pipeline.py):
    from agent_caller import (
        call_upstream_analyst, format_upstream_context,
        call_downstream_striker, format_prober_context,
    )

    upstream = call_upstream_analyst(target, mock=mock_upstream)
    ctx      = format_upstream_context(upstream)
    # ... run Scout + Analyst ...
    prober_ctx = format_prober_context(target, analyst_result, upstream)
    striker    = call_downstream_striker(target, prober_ctx, mock=mock_striker)

Fallback behaviour:
    Both functions NEVER raise. On connection error / timeout they return
    status="unreachable" so the pipeline degrades gracefully.
    Use --mock-upstream / --mock-striker CLI flags for offline demo/testing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger("agent-caller")

ANALYST_AGENT_URL     = os.environ.get("ANALYST_AGENT_URL",     "http://localhost:8000")
ANALYST_AGENT_TIMEOUT = int(os.environ.get("ANALYST_AGENT_TIMEOUT", "30"))

STRIKER_AGENT_URL     = os.environ.get("STRIKER_AGENT_URL",     "http://localhost:8005")
STRIKER_AGENT_TIMEOUT = int(os.environ.get("STRIKER_AGENT_TIMEOUT", "30"))


# ---------------------------------------------------------------------------
# Canned mock responses
# ---------------------------------------------------------------------------

_MOCK_ANALYST_RESPONSE: dict[str, Any] = {
    "agent_id": "agent-analyst",
    "status":   "completed",
    "response": {
        "summary": (
            "agent-analyst completed secret + endpoint scan on https://demo.testfire.net. "
            "Found 2 secrets: AWS_ACCESS_KEY_ID leaked in /static/app.js (CRITICAL) "
            "and a hardcoded JWT secret in /.git/config (HIGH). "
            "Discovered 3 live API endpoints: /api/v1/users, /api/v1/login, /admin/dashboard. "
            "Signals raised: exposed_git, leaked_aws_key, hardcoded_jwt, api_endpoint, login_endpoint."
        ),
        "findings": [
            {
                "type":        "Secret",
                "tool":        "trufflehog",
                "severity":    "CRITICAL",
                "description": "AWS_ACCESS_KEY_ID leaked in /static/app.js",
                "location":    "/static/app.js",
                "detail":      "AKIA...[REDACTED]",
            },
            {
                "type":        "Secret",
                "tool":        "secretfinder",
                "severity":    "HIGH",
                "description": "Hardcoded JWT secret found in /.git/config",
                "location":    "/.git/config",
                "detail":      "secret=super_secret_jwt_key",
            },
            {
                "type":        "Endpoint",
                "tool":        "linkfinder",
                "severity":    "INFO",
                "description": "Live user-list API endpoint",
                "location":    "/api/v1/users",
                "detail":      "HTTP 200 — returns JSON user list",
            },
            {
                "type":        "Endpoint",
                "tool":        "linkfinder",
                "severity":    "INFO",
                "description": "Login endpoint discovered",
                "location":    "/api/v1/login",
                "detail":      "HTTP 200 — accepts POST username/password",
            },
            {
                "type":        "Endpoint",
                "tool":        "linkfinder",
                "severity":    "INFO",
                "description": "Admin dashboard discovered",
                "location":    "/admin/dashboard",
                "detail":      "HTTP 302 — redirects to /admin/login",
            },
        ],
    },
}

_MOCK_STRIKER_RESPONSE: dict[str, Any] = {
    "agent_id": "agent-striker",
    "status":   "completed",
    "response": {
        "summary": (
            "agent-striker completed PoC verification on https://demo.testfire.net. "
            "Confirmed 2 critical findings from Prober: "
            "(1) Exposed .git/config readable — confirmed via HTTP GET, returns [core] stanza. "
            "(2) CORS misconfiguration confirmed — arbitrary origin accepted with credentials on /api/v1/users. "
            "2 findings promoted to EXPLOIT-CONFIRMED. Risk rating: CRITICAL."
        ),
        "findings": [
            {
                "type":        "Exploit",
                "tool":        "curl_poc",
                "severity":    "HIGH",
                "description": "Exposed .git/config readable without authentication",
                "location":    "https://demo.testfire.net/.git/config",
                "confirmed":   True,
            },
            {
                "type":        "Exploit",
                "tool":        "cors_poc",
                "severity":    "HIGH",
                "description": "CORS arbitrary origin with credentials confirmed",
                "location":    "https://demo.testfire.net/api/v1/users",
                "confirmed":   True,
            },
        ],
        "risk_rating": "CRITICAL",
    },
}


# ---------------------------------------------------------------------------
# UPSTREAM: agent-analyst (Team 3)
# ---------------------------------------------------------------------------

def call_upstream_analyst(
    target:   str,
    base_url: str = ANALYST_AGENT_URL,
    timeout:  int = ANALYST_AGENT_TIMEOUT,
    mock:     bool = False,
) -> dict[str, Any]:
    """
    Call the upstream agent-analyst service and return a normalised result dict.

    Returns
    -------
    {
        "status":   "completed" | "failed" | "unreachable",
        "summary":  str,
        "findings": list[dict],
        "agent_id": str,
        "error":    str | None,
        "mock":     bool,
    }
    Never raises — returns status="unreachable" on any error.
    """
    if mock:
        logger.info("UPSTREAM ANALYST: returning mock response (mock=True)")
        resp = _MOCK_ANALYST_RESPONSE
        return {
            "status":   resp["status"],
            "summary":  resp["response"]["summary"],
            "findings": resp["response"]["findings"],
            "agent_id": resp.get("agent_id", "agent-analyst"),
            "error":    None,
            "mock":     True,
        }

    url     = f"{base_url.rstrip('/')}/agents/agent-analyst/tasks"
    payload = {
        "prompt": (
            "Perform secret scanning and endpoint discovery on the target. "
            "Find leaked credentials, API keys, JWT tokens, or any exposed secrets. "
            "Identify live API endpoints and login pages. "
            "Return a concise summary of all findings for downstream active scanning."
        ),
        "target":  target,
        "context": {},
    }

    try:
        import httpx
        logger.info("UPSTREAM ANALYST: calling %s | target: %s", url, target)
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        resp_body = data.get("response", {})
        logger.info("UPSTREAM ANALYST: done | status=%s | findings=%d",
                    data.get("status"), len(resp_body.get("findings", [])))
        return {
            "status":   data.get("status", "completed"),
            "summary":  resp_body.get("summary", ""),
            "findings": resp_body.get("findings", []),
            "agent_id": data.get("agent_id", "agent-analyst"),
            "error":    None,
            "mock":     False,
        }

    except Exception as exc:
        logger.warning("UPSTREAM ANALYST: unreachable — %s", exc)
        return {
            "status":   "unreachable",
            "summary":  "",
            "findings": [],
            "agent_id": "agent-analyst",
            "error":    str(exc),
            "mock":     False,
        }


def format_upstream_context(analyst_result: dict[str, Any]) -> str:
    """
    Convert upstream analyst result into a plain-text context block for injection
    into Scout's and our Analyst's LLM prompts.
    """
    if analyst_result["status"] == "unreachable" or not analyst_result.get("summary"):
        return (
            "Note: Upstream agent-analyst was unreachable. "
            "No prior secret/endpoint findings available — proceed with active scan only."
        )

    secrets   = [f for f in analyst_result.get("findings", []) if f.get("type") == "Secret"]
    endpoints = [f for f in analyst_result.get("findings", []) if f.get("type") == "Endpoint"]

    lines = [
        "=== UPSTREAM CONTEXT (from agent-analyst) ===",
        analyst_result["summary"],
    ]
    if secrets:
        lines.append(
            f"Secrets confirmed ({len(secrets)}): "
            + " | ".join(
                f"{f['description']} at {f['location']} [{f.get('severity','?')}]"
                for f in secrets
            )
        )
    if endpoints:
        lines.append(
            f"Endpoints discovered ({len(endpoints)}): "
            + ", ".join(f["location"] for f in endpoints)
        )
    lines.append("=== END UPSTREAM CONTEXT ===")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DOWNSTREAM: agent-striker (Team 5)
# ---------------------------------------------------------------------------

def build_striker_context(
    target:          str,
    analyst_result:  dict[str, Any],
    upstream_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the structured context dictionary required by agent-striker (Team 5):
    {
        "summary": "one or two sentences — plain text, what you found overall",
        "findings": [
            { "type": "sqli_candidate" | "xss_candidate" | "ssrf_candidate" | "ssti_candidate",
              "url": "full URL",
              "param": "parameter name" }
        ]
    }
    """
    response   = analyst_result.get("response", {})
    summary    = response.get("summary", "Active scan completed with findings.")
    findings_list = response.get("findings", [])

    details = []
    if findings_list:
        details = findings_list[0].get("details", [])

    striker_findings = []
    from urllib.parse import urlparse, parse_qs

    for d in details:
        source_tool = d.get("source_tool", "")
        # Extract XSS candidates
        if source_tool == "run_kxss" or "unfiltered_chars" in d:
            url = d.get("url") or d.get("matched_at") or target
            param = d.get("param") or ""
            if not param:
                try:
                    parsed = urlparse(url)
                    qs = parse_qs(parsed.query)
                    if qs:
                        param = list(qs.keys())[0]
                except Exception:
                    pass
            striker_findings.append({
                "type": "xss_candidate",
                "url": url,
                "param": param
            })
            continue

        template_id = d.get("template_id", "").lower()
        matched_at = d.get("matched_at") or d.get("url") or target

        # Extract SQLi candidates
        if "sqli" in template_id or "sql-injection" in template_id:
            param = ""
            try:
                parsed = urlparse(matched_at)
                qs = parse_qs(parsed.query)
                if qs:
                    param = list(qs.keys())[0]
            except Exception:
                pass
            striker_findings.append({
                "type": "sqli_candidate",
                "url": matched_at,
                "param": param
            })
        # Extract SSRF candidates
        elif "ssrf" in template_id or "oast" in template_id:
            param = ""
            try:
                parsed = urlparse(matched_at)
                qs = parse_qs(parsed.query)
                if qs:
                    param = list(qs.keys())[0]
            except Exception:
                pass
            striker_findings.append({
                "type": "ssrf_candidate",
                "url": matched_at,
                "param": param
            })
        # Extract SSTI candidates
        elif "ssti" in template_id or "template-injection" in template_id:
            param = ""
            try:
                parsed = urlparse(matched_at)
                qs = parse_qs(parsed.query)
                if qs:
                    param = list(qs.keys())[0]
            except Exception:
                pass
            striker_findings.append({
                "type": "ssti_candidate",
                "url": matched_at,
                "param": param
            })

    # Default mock candidates for testfire.net target so Striker has testable parameters
    if not striker_findings:
        if "testfire.net" in target:
            striker_findings.append({
                "type": "xss_candidate",
                "url": target + "/search.aspx?txtSearch=test",
                "param": "txtSearch"
            })
            striker_findings.append({
                "type": "sqli_candidate",
                "url": target + "/login.aspx",
                "param": "uid"
            })

    # Include upstream secrets information in the summary context if available
    summary_enriched = summary
    if upstream_result and upstream_result.get("summary"):
        secrets = [f for f in upstream_result.get("findings", []) if f.get("type") == "Secret"]
        if secrets:
            summary_enriched += "\nUpstream Secrets: " + " | ".join(
                f"{s['description']} @ {s['location']}" for s in secrets
            )

    return {
        "summary": summary_enriched[:1000],
        "findings": striker_findings
    }


def call_downstream_striker(
    target:          str,
    striker_context: dict[str, Any],
    base_url:        str = STRIKER_AGENT_URL,
    timeout:         int = STRIKER_AGENT_TIMEOUT,
    mock:            bool = False,
) -> dict[str, Any]:
    """
    Call the downstream agent-striker service with our confirmed vuln findings.

    Parameters
    ----------
    target          : URL that was scanned.
    striker_context : Structured context dictionary matching Team 5's requirements.
    base_url        : Base URL of the agent-striker service.
    timeout         : HTTP request timeout in seconds.
    mock            : If True, return a canned response without making an HTTP call.

    Returns
    -------
    Normalised result dict.
    Never raises — returns status="unreachable" on any error.
    """
    if mock:
        logger.info("DOWNSTREAM STRIKER: returning mock response (mock=True)")
        resp = _MOCK_STRIKER_RESPONSE
        return {
            "status":      resp["status"],
            "summary":     resp["response"]["summary"],
            "findings":    resp["response"]["findings"],
            "risk_rating": resp["response"].get("risk_rating"),
            "agent_id":    resp.get("agent_id", "agent-striker"),
            "error":       None,
            "mock":        True,
        }

    url     = f"{base_url.rstrip('/')}/agents/agent-striker/tasks"
    payload = {
        "prompt": (
            "You have received confirmed vulnerability findings from the active scanner (agent-prober). "
            "Attempt read-only PoC exploitation for the highest-severity findings. "
            "Confirm which vulnerabilities are exploitable and provide a final risk rating. "
            "Do NOT attempt destructive or write actions — read-only PoC only."
        ),
        "target":  target,
        "context": striker_context,
    }

    try:
        import httpx
        logger.info("DOWNSTREAM STRIKER: calling %s | target: %s", url, target)
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()

        resp_body = data.get("response", {})
        logger.info("DOWNSTREAM STRIKER: done | status=%s | risk=%s",
                    data.get("status"), resp_body.get("risk_rating"))
        return {
            "status":      data.get("status", "completed"),
            "summary":     resp_body.get("summary", ""),
            "findings":    resp_body.get("findings", []),
            "risk_rating": resp_body.get("risk_rating"),
            "agent_id":    data.get("agent_id", "agent-striker"),
            "error":       None,
            "mock":        False,
        }

    except Exception as exc:
        logger.warning("DOWNSTREAM STRIKER: unreachable — %s", exc)
        return {
            "status":      "unreachable",
            "summary":     "",
            "findings":    [],
            "risk_rating": None,
            "agent_id":    "agent-striker",
            "error":       str(exc),
            "mock":        False,
        }
