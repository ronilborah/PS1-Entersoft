"""pipeline.py

Day 23 — Multi-Agent Pipeline: Scout → Analyst

USAGE
-----
# Normal run — uses real Groq LLM (requires API access):
    python pipeline.py --target https://demo.testfire.net

# Mock-LLM run — tools fire in mock mode, LLM replaced by deterministic rules
# (works offline, great for demos and capturing output):
    python pipeline.py --target https://demo.testfire.net --mock-llm

# Break mode — simulate Scout timeout (kill):
    python pipeline.py --target https://demo.testfire.net --mock-llm --break-mode kill

# Break mode — garbage input to Scout:
    python pipeline.py --target https://demo.testfire.net --mock-llm --break-mode garbage

# Break mode — artificial latency before Analyst starts:
    python pipeline.py --target https://demo.testfire.net --mock-llm --break-mode delay

# Optional: increase log verbosity:
    python pipeline.py --target https://demo.testfire.net --mock-llm --verbose

BREAK MODES (for step 3 of the assignment)
-------------------------------------------
kill    : Scout's result is replaced with a timeout envelope.
          Simulates the scenario where Scout's LLM call never returns.
          Analyst receives target_live=False and scout_status="timeout".

garbage : The target passed to Scout is replaced with an invalid URL
          (http://[INVALID-HOST-####]), causing httpx to fail.
          Scout returns with no findings. Analyst receives an empty envelope.

delay   : A time.sleep(5) is injected after Scout completes but before
          Analyst starts. Demonstrates latency stacking in sequential pipelines.
          Analyst still runs and produces real output.

These modes are intentional — they expose coordination failures documented
in the writeup.md file.

MOCK-LLM MODE
--------------
--mock-llm replaces the LangGraph ReAct agents with deterministic rule-based
agents that call every Scout/Analyst tool directly. Tool results are still
realistically mocked (TOOL_MOCK_MODE=true), so the HandoffEnvelope and full
failure-mode demonstrations work without any internet/LLM access.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

# ---------------------------------------------------------------------------
# Unset sandbox proxy so real-LLM runs can reach the Groq API directly.
# The IDE injects HTTP_PROXY/HTTPS_PROXY pointing at 127.0.0.1 which blocks
# outbound API calls. Unsetting here means runs from the terminal work fine.
# ---------------------------------------------------------------------------
for _pvar in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
              "ALL_PROXY", "all_proxy"):
    os.environ.pop(_pvar, None)

from dotenv import load_dotenv

load_dotenv()

from agent_scout   import run_scout
from agent_analyst import run_analyst
from agent_caller  import (
    call_upstream_analyst, format_upstream_context,
    call_downstream_striker, build_striker_context,
)
from tools         import get_tool


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline")


# ---------------------------------------------------------------------------
# ANSI colour helpers (disabled on non-TTY / Windows)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty() and os.name != "nt"

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text

def green(t: str)  -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def red(t: str)    -> str: return _c("31", t)
def bold(t: str)   -> str: return _c("1",  t)
def cyan(t: str)   -> str: return _c("36", t)
def dim(t: str)    -> str: return _c("2",  t)


# ---------------------------------------------------------------------------
# Orchestrator helpers
# ---------------------------------------------------------------------------

def _print_separator(label: str = "") -> None:
    width = 72
    if label:
        pad = (width - len(label) - 2) // 2
        print(cyan("─" * pad + f" {label} " + "─" * (width - pad - len(label) - 2)))
    else:
        print(cyan("─" * width))


def _print_envelope(envelope: dict[str, Any]) -> None:
    """Pretty-print the HandoffEnvelope that crosses the Scout → Analyst boundary."""
    _print_separator("HANDOFF ENVELOPE")
    print(f"  target       : {bold(envelope.get('target', 'N/A'))}")
    print(f"  target_live  : {green('True') if envelope.get('target_live') else red('False')}")
    print(f"  status_code  : {envelope.get('status_code', 'N/A')}")
    print(f"  scout_status : {envelope.get('scout_status', 'N/A')}")
    if envelope.get("scout_error"):
        print(f"  scout_error  : {red(envelope['scout_error'])}")
    print(f"  tech_stack   : {envelope.get('tech_stack', [])}")
    print(f"  disc_paths   : {envelope.get('discovered_paths', [])[:5]}{'...' if len(envelope.get('discovered_paths', [])) > 5 else ''}")
    print(f"  signals      : {yellow(', '.join(envelope.get('signal_candidates', [])) or 'none')}")
    print(f"  tools_used   : {envelope.get('scout_tools_used', [])}")
    print()
    print(f"  Scout summary (first 400 chars):")
    summary = envelope.get("scout_summary", "") or ""
    print(dim("  " + summary[:400].replace("\n", "\n  ")))
    _print_separator()


def _build_timeout_envelope(target: str) -> dict[str, Any]:
    """Simulate Scout timing out — the envelope a real timeout would produce."""
    return {
        "target":            target,
        "target_live":       False,
        "status_code":       None,
        "tech_stack":        [],
        "discovered_paths":  [],
        "signal_candidates": [],
        "scout_summary":     "",
        "scout_tools_used":  [],
        "scout_status":      "timeout",
        "scout_error":       "Scout LLM call timed out after 30s (simulated kill)",
    }


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Mock-LLM agents — deterministic tool execution without a live LLM
# ---------------------------------------------------------------------------

def _tool_json(tool_key: str, target: str) -> dict:
    """Run a tool in mock mode and return its parsed result dict."""
    try:
        return get_tool(tool_key).run(target, {})
    except Exception as exc:
        return {"signal_candidates": [], "findings": [], "errors": [str(exc)],
                "live": False, "status_code": None, "tech": [], "mock": True}


def run_scout_mock(target: str, upstream_context: str = "") -> dict[str, Any]:
    """Deterministic Scout: runs httpx → ffuf → nikto, builds HandoffEnvelope."""
    logger.info("=== MOCK SCOUT STARTING | target: %s ===", target)
    print(dim("  [mock-llm] Scout running tools directly (no LLM)"))

    tools_used: list[str] = []
    signal_candidates: set[str] = set()
    tech_stack: list[str] = []
    discovered_paths: list[str] = []
    target_live = False
    status_code = None
    scout_summary_lines: list[str] = []

    # Step 1: httpx — check liveness
    print(dim("    → run_httpx"))
    httpx_r = _tool_json("httpx", target)
    tools_used.append("run_httpx")
    # httpx packs live/status_code/tech directly AND inside findings[0]
    for f in httpx_r.get("findings", []):
        if isinstance(f, dict):
            if f.get("live"):         target_live = True
            if f.get("status_code"): status_code = f["status_code"]
            tech_stack.extend(f.get("tech", []))
    if httpx_r.get("live"):         target_live = True
    if httpx_r.get("status_code"): status_code = httpx_r["status_code"]
    tech_stack.extend(httpx_r.get("tech", []))
    signal_candidates.update(httpx_r.get("signal_candidates", []))
    scout_summary_lines.append(
        f"httpx: target {'LIVE' if target_live else 'UNREACHABLE'} "
        f"(HTTP {status_code}), tech={list(set(tech_stack))}"
    )

    if not target_live:
        scout_summary_lines.append("Scout halted — target not live.")
        logger.info("=== MOCK SCOUT COMPLETED | target not live ===")
        return {
            "target": target, "target_live": False, "status_code": status_code,
            "tech_stack": [], "discovered_paths": [], "signal_candidates": [],
            "scout_summary": "\n".join(scout_summary_lines),
            "scout_tools_used": tools_used,
            "scout_status": "completed", "scout_error": None,
        }

    # Step 2: ffuf — discover paths
    print(dim("    → run_ffuf"))
    ffuf_r = _tool_json("ffuf", target)
    tools_used.append("run_ffuf")
    signal_candidates.update(ffuf_r.get("signal_candidates", []))
    for f in ffuf_r.get("findings", []):
        if isinstance(f, dict):
            url = f.get("url") or f.get("input", "")
            if url: discovered_paths.append(url)
    scout_summary_lines.append(
        f"ffuf: {len(discovered_paths)} path(s) found — "
        f"{', '.join(discovered_paths[:4])}{'...' if len(discovered_paths) > 4 else ''}"
    )

    # Step 3: nikto — server-level checks
    print(dim("    → run_nikto"))
    nikto_r = _tool_json("nikto", target)
    tools_used.append("run_nikto")
    signal_candidates.update(nikto_r.get("signal_candidates", []))
    nikto_findings = nikto_r.get("findings", [])
    scout_summary_lines.append(
        f"nikto: {len(nikto_findings)} finding(s) — "
        f"signals: {sorted(nikto_r.get('signal_candidates', []))}"
    )

    scout_summary_lines.append(
        f"Surface summary: target live, tech={sorted(set(tech_stack))}, "
        f"signals={sorted(signal_candidates)}. Handing off to Analyst."
    )

    # Inject upstream context at the end of Scout summary so Analyst can read it
    if upstream_context:
        scout_summary_lines.append(upstream_context)

    envelope = {
        "target":            target,
        "target_live":       target_live,
        "status_code":       status_code,
        "tech_stack":        sorted(set(tech_stack)),
        "discovered_paths":  discovered_paths,
        "signal_candidates": sorted(signal_candidates),
        "scout_summary":     "\n".join(scout_summary_lines),
        "scout_tools_used":  tools_used,
        "scout_status":      "completed",
        "scout_error":       None,
    }
    logger.info("=== MOCK SCOUT COMPLETED | signals: %s ===", envelope["signal_candidates"])
    return envelope


def run_analyst_mock(envelope: dict[str, Any], upstream_context: str = "") -> dict[str, Any]:
    """Deterministic Analyst: reads HandoffEnvelope, picks tools by signal rules."""
    target       = envelope.get("target", "unknown")
    scout_status = envelope.get("scout_status", "completed")
    target_live  = envelope.get("target_live", False)
    signals      = set(envelope.get("signal_candidates", []))

    # Enrich signals from upstream agent-analyst context (Analyst→Prober handoff)
    if upstream_context:
        uc = upstream_context.lower()
        if "login_endpoint" in uc or "/login" in uc or "login" in uc:
            signals.add("login_endpoint")
        if "api_endpoint" in uc or "/api/" in uc:
            signals.add("api_endpoint")
        if "cors" in uc:
            signals.add("cors_misconfiguration")
        if "exposed_git" in uc or "/.git" in uc:
            signals.add("exposed_git")
        if "exposed_env" in uc or "/.env" in uc:
            signals.add("exposed_env")

    logger.info("=== MOCK ANALYST STARTING | target: %s | live: %s | signals: %s ===",
                target, target_live, sorted(signals))
    print(dim("  [mock-llm] Analyst reading HandoffEnvelope, picking tools by rule"))

    # Cascading failure guard — Analyst halts if Scout didn't complete
    if scout_status in ("failed", "timeout") or not target_live:
        reason = (
            f"Analyst blocked: Scout status='{scout_status}', target_live={target_live}. "
            f"Cannot perform vulnerability analysis without a confirmed live target "
            f"and successful Scout run."
        )
        print(dim(f"  [mock-llm] {reason}"))
        logger.info("=== MOCK ANALYST HALTED — upstream failure ===")
        return {
            "agent_id": "agent-analyst",
            "status":   "completed",
            "response": {
                "summary":  reason,
                "findings": [{"signal_candidates": [], "tools_used": [],
                              "tool_errors": [], "intent_log": [], "details": []}],
                "scout_envelope": envelope,
            },
        }

    # Tool selection rules (mirrors the Analyst system prompt)
    tools_to_run: list[tuple[str, str]] = []  # (tool_key, intent)

    has_nginx_or_apache = any(t in envelope.get("tech_stack", [])
                               for t in ["nginx", "Apache", "apache"])
    if has_nginx_or_apache or signals & {"exposed_git", "exposed_env",
                                          "missing_csp_header", "missing_hsts_header"}:
        tools_to_run.append(("nuclei_active",
            "Confirm active misconfigurations and CVEs flagged by Scout signals"))

    if target.startswith("https://") or "weak_tls" in signals:
        tools_to_run.append(("testssl_deep",
            "Check for weak TLS protocol versions and vulnerable cipher suites"))

    if "cors_misconfiguration" in signals or "api_endpoint" in signals:
        tools_to_run.append(("corsy",
            "Confirm CORS misconfiguration — check for arbitrary origin reflection"))

    if "login_endpoint" in signals or "reflected_xss_candidate" in signals:
        tools_to_run.append(("kxss",
            "Check login/parameter URLs for reflected XSS character leakage"))

    # Default fallback if no specific signals matched
    if not tools_to_run:
        tools_to_run.append(("nuclei_active",
            "No specific signals — running nuclei as broad default scan"))

    # Cap at 3 tools
    tools_to_run = tools_to_run[:3]

    findings: list[dict]        = []
    analyst_signals: set[str]   = set()
    tools_used: list[str]       = []
    intent_log: list[dict]      = []
    summary_lines: list[str]    = [
        f"Analyst received Scout envelope: target_live={target_live}, "
        f"signals={sorted(signals)}, paths={envelope.get('discovered_paths', [])[:3]}",
    ]

    for tool_key, intent in tools_to_run:
        print(dim(f"    → run_{tool_key}  [{intent[:60]}]"))
        r = _tool_json(tool_key, target)
        tool_name = f"run_{tool_key}"
        tools_used.append(tool_name)
        intent_log.append({"tool": tool_name, "intent": intent, "fulfilled": True})
        for f in r.get("findings", []):
            if isinstance(f, dict):
                f["source_tool"] = tool_name
                findings.append(f)
        new_signals = r.get("signal_candidates", [])
        analyst_signals.update(new_signals)
        summary_lines.append(
            f"{tool_name}: {len(r.get('findings', []))} finding(s), "
            f"signals={new_signals}, errors={r.get('errors', [])}"
        )

    # Determine overall risk from combined signals
    critical_signals = {"rce_template", "sql_injection_template", "ssrf_template"}
    high_signals     = {"weak_tls_version_or_ciphers", "cors_wildcard_with_credentials",
                        "reflected_xss_candidate", "confirmed_active_vulnerability"}
    medium_signals   = {"exposed_git", "exposed_env", "exposed_admin_panel",
                        "backup_file", "missing_csp_header", "missing_hsts_header"}
    all_signals = analyst_signals | signals
    if all_signals & critical_signals:  risk = "Critical"
    elif all_signals & high_signals:    risk = "High"
    elif all_signals & medium_signals:  risk = "Medium"
    else:                               risk = "Low / Informational"

    summary_lines.append(
        f"\nOverall risk rating: {risk}. "
        f"Confirmed signals: {sorted(analyst_signals)}. "
        f"Scout signals (not re-tested): {sorted(signals - analyst_signals)}."
    )
    analyst_summary = "\n".join(summary_lines)

    logger.info("=== MOCK ANALYST COMPLETED | tools_used: %s | signals: %s ===",
                tools_used, sorted(analyst_signals))
    return {
        "agent_id": "agent-analyst",
        "status":   "completed",
        "response": {
            "summary":  analyst_summary,
            "findings": [{
                "signal_candidates": sorted(analyst_signals),
                "tools_used":        tools_used,
                "tool_errors":       [],
                "intent_log":        intent_log,
                "details":           findings,
            }],
            "scout_envelope": envelope,
        },
    }


def run_pipeline(target: str, break_mode: str | None = None,
                 mock_llm: bool = False,
                 upstream_url: str = "http://localhost:8000",
                 mock_upstream: bool = False,
                 striker_url: str = "http://localhost:8005",
                 mock_striker: bool = False) -> dict[str, Any]:
    """
    Orchestrate the full Analyst→Prober pipeline.

    Phase 0  — Call upstream agent-analyst (Team 3) for secret/endpoint findings.
    Phase 1  — Run Scout (surface discovery: httpx, ffuf, nikto).
    Phase 2  — Run Analyst (active vuln scan: nuclei, testssl, corsy, kxss),
               with upstream context + Scout findings merged as input context.

    Parameters
    ----------
    target        : The URL to scan.
    break_mode    : One of "kill", "garbage", "delay", or None (happy path).
    mock_llm      : If True, use deterministic rule-based agents instead of LLM.
    upstream_url  : Base URL of the upstream agent-analyst service.
    mock_upstream : If True, use a canned mock response for the upstream agent.

    Returns
    -------
    A dict containing the full pipeline result:
    {
        "target":           str,
        "break_mode":       str | None,
        "mock_llm":         bool,
        "upstream_result":  dict,     — what agent-analyst returned
        "scout_envelope":   dict,     — what crossed the Scout boundary
        "analyst_result":   dict,     — Analyst's full output
        "timing": {
            "upstream_seconds":  float,
            "scout_seconds":     float,
            "injected_delay":    float,
            "analyst_seconds":   float,
            "total_seconds":     float,
        }
    }
    """
    pipeline_start = time.monotonic()

    print()
    _print_separator("PIPELINE START")
    print(f"  target        : {bold(target)}")
    print(f"  break_mode    : {yellow(break_mode) if break_mode else green('None (happy path)')}")
    print(f"  llm mode      : {dim('mock (deterministic rules)') if mock_llm else green('real LLM (Groq)')}")
    print(f"  upstream agent: {dim('mock response') if mock_upstream else cyan(upstream_url)}")
    print(f"  striker agent : {dim('mock response') if mock_striker else cyan(striker_url)}")
    print()

    # -----------------------------------------------------------------------
    # PHASE 0: Upstream agent-analyst (Team 3 — secret/endpoint scanner)
    # -----------------------------------------------------------------------
    _print_separator("PHASE 0 — Upstream agent-analyst")
    upstream_start = time.monotonic()
    upstream_result = call_upstream_analyst(
        target, base_url=upstream_url, mock=mock_upstream
    )
    upstream_seconds = time.monotonic() - upstream_start
    upstream_context_str = format_upstream_context(upstream_result)

    status_icon = green("ok") if upstream_result["status"] == "completed" else yellow(upstream_result["status"])
    print(f"  agent-analyst : {status_icon}  "
          f"({upstream_seconds:.2f}s)  "
          f"{'[mock]' if upstream_result['mock'] else '[live]'}")
    if upstream_result["error"]:
        print(f"  error         : {red(upstream_result['error'][:120])}")
    secrets   = [f for f in upstream_result["findings"] if f.get("type") == "Secret"]
    endpoints = [f for f in upstream_result["findings"] if f.get("type") == "Endpoint"]
    print(f"  secrets found : {yellow(str(len(secrets)))}")
    print(f"  endpoints     : {cyan(', '.join(f['location'] for f in endpoints)) or 'none'}")
    if upstream_result.get("summary"):
        print(f"  summary       :")
        print(dim("  " + upstream_result["summary"][:300].replace("\n", "\n  ")))
    print()

    # -----------------------------------------------------------------------
    # PHASE 1: Scout
    # -----------------------------------------------------------------------
    scout_target = target

    if break_mode == "garbage":
        # Feed Scout an invalid target so httpx fails and returns no findings.
        # The real target is preserved in the envelope for the Analyst to see.
        scout_target = "http://[INVALID-HOST-99999]"
        print(yellow("[BREAK: garbage] Scout will receive invalid target: ") + scout_target)
        print()

    _print_separator("PHASE 1 — Scout Agent")
    scout_start = time.monotonic()

    if break_mode == "kill":
        # Simulate Scout timing out — skip calling the real Scout entirely.
        print(red("[BREAK: kill] Simulating Scout timeout — replacing result with timeout envelope"))
        print()
        envelope = _build_timeout_envelope(target)
        scout_seconds = 0.0
    else:
        # Pass upstream context into mock Scout so it appears in the summary.
        # The real Scout (LLM) receives just the target — upstream context is
        # merged at the Analyst stage instead.
        if mock_llm:
            envelope = run_scout_mock(scout_target, upstream_context_str)
        else:
            envelope = run_scout(scout_target)
        scout_seconds = time.monotonic() - scout_start

        # For garbage mode: patch the envelope's target back to the real target
        # so the Analyst knows what it was supposed to scan, even though Scout
        # returned no useful findings.
        if break_mode == "garbage":
            envelope["target"] = target
            if not envelope.get("scout_error"):
                envelope["scout_error"] = f"Scout received garbage target ({scout_target}); no findings."

    print(f"\n  Scout completed in {scout_seconds:.2f}s\n")
    _print_envelope(envelope)

    # -----------------------------------------------------------------------
    # INJECTED DELAY (delay break mode)
    # -----------------------------------------------------------------------
    injected_delay = 0.0
    if break_mode == "delay":
        injected_delay = 5.0
        print(yellow(f"[BREAK: delay] Injecting {injected_delay}s artificial delay before Analyst starts..."))
        time.sleep(injected_delay)
        print(yellow(f"[BREAK: delay] Delay complete. Analyst starting now.\n"))

    # -----------------------------------------------------------------------
    # PHASE 2: Analyst
    # -----------------------------------------------------------------------
    _print_separator("PHASE 2 — Analyst Agent")
    analyst_start = time.monotonic()

    if mock_llm:
        # Mock Analyst: still uses envelope for rule-based signal detection,
        # but upstream_context enriches the signal set.
        analyst_result = run_analyst_mock(envelope, upstream_context_str)
    else:
        # Real LLM Analyst: merge upstream context + Scout summary into one
        # context string. The Analyst reasons over both to pick tools.
        scout_summary = envelope.get("scout_summary", "")
        merged_context = (
            (upstream_context_str + "\n\n" + scout_summary).strip()
            if upstream_context_str else scout_summary
        )
        analyst_result = run_analyst(target, merged_context)

    analyst_seconds = time.monotonic() - analyst_start

    # -----------------------------------------------------------------------
    # PHASE 3: Downstream agent-striker (Team 5 — exploit / PoC / reporting)
    # -----------------------------------------------------------------------
    _print_separator("PHASE 3 — Downstream agent-striker")
    striker_start   = time.monotonic()
    prober_ctx      = build_striker_context(target, analyst_result, upstream_result)
    striker_result  = call_downstream_striker(
        target, prober_ctx, base_url=striker_url, mock=mock_striker
    )
    striker_seconds = time.monotonic() - striker_start

    striker_icon = green("ok") if striker_result["status"] == "completed" else yellow(striker_result["status"])
    print(f"  agent-striker : {striker_icon}  "
          f"({striker_seconds:.2f}s)  "
          f"{'[mock]' if striker_result['mock'] else '[live]'}")
    if striker_result["error"]:
        print(f"  error         : {red(striker_result['error'][:120])}")
    exploits = [f for f in striker_result["findings"] if f.get("confirmed")]
    print(f"  confirmed PoCs: {red(str(len(exploits))) if exploits else dim('0')}")
    if striker_result.get("risk_rating"):
        colour = red if striker_result["risk_rating"] == "CRITICAL" else yellow
        print(f"  risk rating   : {colour(striker_result['risk_rating'])}")
    if striker_result.get("summary"):
        print(f"  summary       :")
        print(dim("  " + striker_result["summary"][:300].replace("\n", "\n  ")))
    print()

    total_seconds = time.monotonic() - pipeline_start

    # -----------------------------------------------------------------------
    # Final summary
    # -----------------------------------------------------------------------
    _print_separator("PIPELINE RESULT")
    print(f"  Upstream: {green('ok') if upstream_result['status'] == 'completed' else yellow(upstream_result['status'])}  ({upstream_result.get('timing_hint', upstream_seconds):.2f}s)")
    print(f"  Scout   : {green(envelope.get('scout_status','?')) if envelope.get('scout_status') == 'completed' else red(envelope.get('scout_status','?'))}  ({scout_seconds:.2f}s)")
    print(f"  Analyst : {green(analyst_result.get('status','?')) if analyst_result.get('status') == 'completed' else red(analyst_result.get('status','?'))}  ({analyst_seconds:.2f}s)")
    print(f"  Striker : {green(striker_result['status']) if striker_result['status'] == 'completed' else yellow(striker_result['status'])}  ({striker_seconds:.2f}s)")
    if injected_delay:
        print(f"  Injected delay: {yellow(f'{injected_delay:.1f}s')}")
    print(f"  Total   : {total_seconds:.2f}s")

    if analyst_result.get("error"):
        print(f"  Error   : {red(analyst_result['error'])}")

    response = analyst_result.get("response", {})
    if isinstance(response, dict):
        findings_block = response.get("findings", [{}])
        if findings_block and isinstance(findings_block, list):
            fb = findings_block[0]
            print(f"  Tools used by Analyst : {fb.get('tools_used', [])}")
            print(f"  Analyst signals found : {yellow(', '.join(fb.get('signal_candidates', [])) or 'none')}")

        print("\n  Analyst summary (first 600 chars):")
        analyst_summary = response.get("summary", "") or ""
        print(dim("  " + analyst_summary[:600].replace("\n", "\n  ")))

    _print_separator()
    print()

    return {
        "target":          target,
        "break_mode":      break_mode,
        "mock_llm":        mock_llm,
        "upstream_result": upstream_result,
        "scout_envelope":  envelope,
        "analyst_result":  analyst_result,
        "striker_result":  striker_result,
        "timing": {
            "upstream_seconds": upstream_seconds,
            "scout_seconds":    scout_seconds,
            "injected_delay":   injected_delay,
            "analyst_seconds":  analyst_seconds,
            "striker_seconds":  striker_seconds,
            "total_seconds":    total_seconds,
        },
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Day 23 — Scout → Analyst multi-agent pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Break modes:
  kill     Simulate Scout timeout. Analyst receives an empty envelope.
  garbage  Feed Scout an invalid URL. httpx fails, no findings propagate.
  delay    Inject 5s latency between Scout and Analyst (latency stacking).

Examples:
  python pipeline.py --target https://demo.testfire.net --mock-llm
  python pipeline.py --target https://demo.testfire.net --mock-llm --break-mode kill
  python pipeline.py --target https://demo.testfire.net --mock-llm --break-mode garbage
  python pipeline.py --target https://demo.testfire.net --mock-llm --break-mode delay
  python pipeline.py --target https://demo.testfire.net  # real LLM (needs Groq access)
        """,
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL to scan (e.g. https://demo.testfire.net)",
    )
    parser.add_argument(
        "--break-mode", "-b",
        choices=["kill", "garbage", "delay"],
        default=None,
        help="Intentional failure mode for step 3 of the assignment",
    )
    parser.add_argument(
        "--mock-llm", "-m",
        action="store_true",
        help="Use deterministic rule-based agents instead of real LLM (works offline)",
    )
    parser.add_argument(
        "--upstream-url",
        default="http://localhost:8000",
        help="Base URL of the upstream agent-analyst service (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--mock-upstream",
        action="store_true",
        help="Use a canned mock response for the upstream agent-analyst (no HTTP call)",
    )
    parser.add_argument(
        "--striker-url",
        default="http://localhost:8005",
        help="Base URL of the downstream agent-striker service (default: http://localhost:8005)",
    )
    parser.add_argument(
        "--mock-striker",
        action="store_true",
        help="Use a canned mock response for the downstream agent-striker (no HTTP call)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write full pipeline result as JSON to this file path",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    pipeline_result = run_pipeline(
        target=args.target,
        break_mode=args.break_mode,
        mock_llm=args.mock_llm,
        upstream_url=args.upstream_url,
        mock_upstream=args.mock_upstream,
        striker_url=args.striker_url,
        mock_striker=args.mock_striker,
    )

    if args.output:
        out_path = args.output
        with open(out_path, "w") as f:
            json.dump(pipeline_result, f, indent=2, default=str)
        print(f"Full pipeline result written to: {out_path}")
