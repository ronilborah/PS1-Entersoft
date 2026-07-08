"""agent_analyst.py

Analyst Agent — Day 23 Multi-Agent Pipeline (Agent B)

ROLE
----
Analyst is the second agent in the pipeline. It receives Scout's HandoffEnvelope
and runs targeted vulnerability analysis based on what Scout actually found.
It does NOT re-run Scout's discovery tools.

KEY DESIGN: the Analyst reads the HandoffEnvelope to make tool decisions:
  - If target_live=False → stop immediately, do not call any tools
  - If "weak_tls" / "https" hinted in tech/signals → prioritise run_testssl_deep
  - If "exposed_git" or "exposed_env" in signals → escalate with run_nuclei_active
  - If "cors" in signals → run run_corsy
  - If discovered paths include param-bearing URLs → run run_kxss
  - Default fallback → run_nuclei_active for broad active scan

TOOLS AVAILABLE
---------------
- run_nuclei_active  : active vulnerability + misconfiguration templates
- run_testssl_deep   : deep TLS/SSL protocol and cipher analysis
- run_corsy          : CORS misconfiguration detection
- run_kxss           : reflected XSS parameter reflection check

INPUT: HandoffEnvelope from agent_scout.run_scout()
OUTPUT: standard agent result dict with summary + findings
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools import get_tool

logger = logging.getLogger("agent-analyst")

# ---------------------------------------------------------------------------
# LLM — same Groq endpoint as the main agent
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "qwen2.5:7b")

llm = ChatOpenAI(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_BASE_URL,
    api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
    temperature=0,
)


# ---------------------------------------------------------------------------
# Tool wrappers — Analyst's restricted tool set (vuln analysis only)
# ---------------------------------------------------------------------------

def _run(tool_key: str, target: str) -> str:
    """Run one tool and return compact JSON for the LLM Observation step."""
    logger.info(">>> ANALYST TOOL: %s | target: %s", tool_key, target)
    try:
        result = get_tool(tool_key).run(target, {})
        return json.dumps({
            "signal_candidates": result.get("signal_candidates", []),
            "findings":          result.get("findings", [])[:10],
            "errors":            result.get("errors", []),
            "mock":              result.get("mock", True),
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": f"{tool_key} raised {type(exc).__name__}: {exc}"})


@tool
def run_nuclei_active(target: str) -> str:
    """Run nuclei active scan templates (http/vulnerabilities and http/misconfiguration)
    against the target. Finds missing security headers, exposed configs, known CVE
    matches, and active misconfigurations. Best general-purpose vulnerability scanner."""
    return _run("nuclei_active", target)


@tool
def run_testssl_deep(target: str) -> str:
    """Run a deep TLS/SSL analysis on the target. Checks for weak protocol versions
    (TLS 1.0, TLS 1.1, SSLv3), vulnerable cipher suites, and known TLS vulnerabilities
    (BREACH, BEAST, LUCKY13, POODLE). Use when target serves HTTPS or when Scout
    found TLS-related signals."""
    return _run("testssl_deep", target)


@tool
def run_corsy(target: str) -> str:
    """Test for CORS misconfigurations — checks whether the server reflects arbitrary
    origins or whitelists null, allowing cross-origin data theft. Use when Scout found
    cors_misconfiguration signal or an API endpoint."""
    return _run("corsy", target)


@tool
def run_kxss(target: str) -> str:
    """Test the target URL for reflected XSS by checking which special characters
    are returned unfiltered in the response. Use when Scout found login endpoints
    or paths with query parameters."""
    return _run("kxss", target)


ANALYST_TOOLS = [run_nuclei_active, run_testssl_deep, run_corsy, run_kxss]


# ---------------------------------------------------------------------------
# System prompt — vuln analysis only, informed by HandoffEnvelope
# ---------------------------------------------------------------------------

ANALYST_SYSTEM_PROMPT = """You are agent-analyst, a specialist security vulnerability analysis agent.

You receive a summarized context from a Scout agent that has already done surface discovery.
Your job is to analyse what Scout found and run targeted vulnerability scans.
Do NOT repeat Scout's discovery work (no httpx, no ffuf, no nikto).

Your allowed tools: run_nuclei_active, run_testssl_deep, run_corsy, run_kxss.

DECISION RULES (read the Scout summary carefully):
1. If the summary indicates the target is offline, unreachable, or live status is False → stop immediately. Report that target is unreachable and you cannot run vulnerability analysis.
2. If the summary indicates Scout failed, timed out, or had an error → stop immediately. Report the upstream failure and that analysis is blocked.
3. If the target is live:
   a. If the summary mentions "nginx", "Apache", or "exposed_git" or "exposed_env" → run run_nuclei_active first.
   b. If the target URL starts with "https://" → also run run_testssl_deep.
   c. If the summary mentions "cors_misconfiguration" or "api_endpoint" → run run_corsy.
   d. If the summary mentions "login_endpoint" or "reflected_xss_candidate" → run run_kxss.
   e. If none of the above conditions are met → run run_nuclei_active as default.
4. Run at most 3 tools. Stop when you have enough to write a vulnerability summary.

Before every tool call, write your reasoning in this exact format:
Thought: [what the Scout found, and why this tool is the right next step]
Intent: [one sentence — what vulnerability this tool call is trying to confirm]
Fulfilled: [True or False — did the previous tool confirm its intent? N/A for first tool]

Your final answer MUST:
- Acknowledge the Scout's key findings that informed your tool choices
- List confirmed vulnerabilities with severity and tool that found them
- List signals that turned out to be false positives or unconfirmed
- Give an overall risk rating: Critical / High / Medium / Low / Informational"""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_analyst(target: str, context: str) -> dict[str, Any]:
    """Run the Analyst agent using a context string from the Scout.

    If target is offline or Scout failed, the Analyst will detect this from
    the context and halt without calling any tools.

    Returns a standard result dict:
    {
        "agent_id": "agent-analyst",
        "status":   "completed" | "failed",
        "response": { "summary": str, "findings": [...] },
        "error":    str | None,
    }
    """
    context_lower = context.lower()
    is_offline = "offline" in context_lower or "unreachable" in context_lower or "not live" in context_lower
    is_failed = "failed" in context_lower or "timeout" in context_lower or "error" in context_lower or not context.strip()

    # Reconstruct a basic envelope for backward compatibility
    envelope = {
        "target": target,
        "target_live": not is_offline,
        "scout_status": "failed" if is_failed else "completed",
        "scout_summary": context,
    }

    if is_offline or is_failed:
        reason = (
            f"Analyst blocked: Scout status='failed' or target_live=False. "
            f"Cannot perform vulnerability analysis without a confirmed live target "
            f"and successful Scout run."
        )
        logger.info("=== ANALYST HALTED — upstream failure ===")
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

    logger.info("=== ANALYST STARTING | target: %s ===", target)

    # Build the prompt that injects the Scout summary as context
    full_prompt = (
        f"Target: {target}\n"
        f"Task: Perform vulnerability analysis based on Scout's findings below.\n\n"
        f"=== SCOUT SUMMARY ===\n"
        f"{context}\n"
        f"=== END SCOUT SUMMARY ===\n\n"
        f"Use the Scout Summary above to choose which tools to run and why."
    )

    try:
        agent_graph = create_react_agent(
            llm,
            ANALYST_TOOLS,
            prompt=ANALYST_SYSTEM_PROMPT,
        )

        result = agent_graph.invoke(
            {"messages": [("user", full_prompt)]},
            config={"recursion_limit": 15},
        )

        # -----------------------------------------------------------------------
        # Parse message history to extract structured findings
        # -----------------------------------------------------------------------
        findings: list[dict]        = []
        signal_candidates: set[str] = set()
        tools_used: list[str]       = []
        intent_log: list[dict]      = []
        current_intent              = "N/A"

        for msg in result["messages"]:
            msg_type = type(msg).__name__

            if msg_type == "AIMessage":
                content = getattr(msg, "content", "") or ""
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("Intent:"):
                        current_intent = line[len("Intent:"):].strip()
                    elif line.startswith("Fulfilled:"):
                        fulfilled_str = line[len("Fulfilled:"):].strip()
                        if intent_log:
                            intent_log[-1]["fulfilled"] = (fulfilled_str == "True")

            if msg_type == "ToolMessage":
                tool_name = getattr(msg, "name", "unknown")
                tools_used.append(tool_name)

                intent_log.append({
                    "tool":      tool_name,
                    "intent":    current_intent,
                    "fulfilled": None,
                })

                try:
                    parsed = json.loads(msg.content)
                    for f in parsed.get("findings", []):
                        f["source_tool"] = tool_name
                        findings.append(f)
                    signal_candidates.update(parsed.get("signal_candidates", []))
                except (json.JSONDecodeError, AttributeError):
                    pass

                current_intent = "N/A"

        if intent_log and intent_log[-1]["fulfilled"] is None:
            intent_log[-1]["fulfilled"] = True

        analyst_summary = result["messages"][-1].content or ""
        logger.info("=== ANALYST COMPLETED | tools_used: %s | signals: %s ===",
                    tools_used, sorted(signal_candidates))

        return {
            "agent_id": "agent-analyst",
            "status":   "completed",
            "response": {
                "summary":  analyst_summary,
                "findings": [{
                    "signal_candidates": sorted(signal_candidates),
                    "tools_used":        list(dict.fromkeys(tools_used)),
                    "tool_errors":       [],
                    "intent_log":        intent_log,
                    "details":           findings,
                }],
                # Include the envelope so the full pipeline output is self-contained
                "scout_envelope": envelope,
            },
        }

    except Exception as exc:
        logger.exception("Analyst agent failed")
        return {
            "agent_id": "agent-analyst",
            "status":   "failed",
            "response": {},
            "error":    str(exc),
        }
