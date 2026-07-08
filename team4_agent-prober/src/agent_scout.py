"""agent_scout.py

Scout Agent — Day 23 Multi-Agent Pipeline (Agent A)

ROLE
----
Scout is the first agent in the pipeline. Its job is surface discovery:
confirm the target is live, enumerate exposed paths/tech, and identify
the attack surface. It does NOT attempt vulnerability analysis.

It produces a HandoffEnvelope dict that the orchestrator (pipeline.py)
passes directly to the Analyst agent (agent_analyst.py).

TOOLS AVAILABLE
---------------
- run_httpx      : confirm liveness, get status code + tech stack
- run_ffuf       : fuzz for hidden directories and sensitive paths
- run_nikto      : broad web server check, banner/header findings

HANDOFF ENVELOPE (output schema)
---------------------------------
{
    "target"           : str         — original target URL
    "target_live"      : bool        — did httpx confirm the target is up?
    "status_code"      : int | None  — HTTP status from httpx
    "tech_stack"       : list[str]   — detected tech (e.g. ["nginx", "WordPress"])
    "discovered_paths" : list[str]   — paths found by ffuf (e.g. ["/admin", "/.git"])
    "signal_candidates": list[str]   — Scout's aggregated signals
    "scout_summary"    : str         — verbatim final LLM narrative
    "scout_tools_used" : list[str]   — tools Scout called (in order)
    "scout_status"     : str         — "completed" | "failed"
    "scout_error"      : str | None  — error message if Scout failed
}
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

logger = logging.getLogger("agent-scout")

# ---------------------------------------------------------------------------
# LLM — same Groq endpoint as the main agent
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "qwen2.5:7b")

llm = ChatOpenAI(
    model=OLLAMA_BASE_URL,
    base_url=OLLAMA_BASE_URL,
    api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
    temperature=0,
)

# Rebuild the LLM with correct model name (base_url was accidentally used above)
llm = ChatOpenAI(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_BASE_URL,
    api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
    temperature=0,
)


# ---------------------------------------------------------------------------
# Tool wrappers — Scout's restricted tool set (discovery only)
# ---------------------------------------------------------------------------

def _run(tool_key: str, target: str) -> str:
    """Run one tool and return compact JSON for the LLM Observation step."""
    logger.info(">>> SCOUT TOOL: %s | target: %s", tool_key, target)
    try:
        result = get_tool(tool_key).run(target, {})
        return json.dumps({
            "signal_candidates": result.get("signal_candidates", []),
            "findings":          result.get("findings", [])[:10],
            "errors":            result.get("errors", []),
            "mock":              result.get("mock", True),
            # pass through httpx-specific live/tech fields so LLM can read them
            "live":              result.get("live"),
            "status_code":       result.get("status_code"),
            "tech":              result.get("tech", []),
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": f"{tool_key} raised {type(exc).__name__}: {exc}"})


@tool
def run_httpx(target: str) -> str:
    """Confirm the target URL is live, get its HTTP status code, page title,
    and detected technology stack (web server, CMS, framework hints).
    ALWAYS call this first — if the target is not live, stop and report it."""
    return _run("httpx", target)


@tool
def run_ffuf(target: str) -> str:
    """Fuzz the target for hidden directories, backup files, admin panels,
    .git directories, .env files, and other sensitive paths.
    Call this after confirming the target is live with run_httpx."""
    return _run("ffuf", target)


@tool
def run_nikto(target: str) -> str:
    """Run nikto web server scanner for known misconfigurations, missing
    security headers, dangerous files, and outdated software banners.
    Provides broad surface coverage — use after ffuf to complement path findings."""
    return _run("nikto", target)


SCOUT_TOOLS = [run_httpx, run_ffuf, run_nikto]

# ---------------------------------------------------------------------------
# System prompt — discovery only, no vuln analysis
# ---------------------------------------------------------------------------

SCOUT_SYSTEM_PROMPT = """You are agent-scout, a specialist security reconnaissance agent.

Your ONLY job is surface discovery. You map the target's attack surface and hand off
your findings to a downstream analyst agent. Do NOT attempt to confirm or exploit
vulnerabilities yourself.

Your allowed tools: run_httpx, run_ffuf, run_nikto.

Rules:
1. ALWAYS run run_httpx first. If target_live is False (unreachable), stop immediately
   and report that — do not call any other tools.
2. If the target is live, run run_ffuf to discover hidden paths and interesting files.
3. Run run_nikto for broad server-level checks.
4. Stop after 3 tool calls maximum. Do not loop.

Before every tool call, write your reasoning in this exact format:
Thought: [what you know so far and why this tool is next]
Intent: [one sentence — what this specific tool call is trying to discover]
Fulfilled: [True or False — did the previous tool answer its intent? Write N/A for first tool]

Your final answer MUST include:
- Whether the target is live and its HTTP status code
- Technologies detected (if any)
- Interesting paths found (admin panels, .git, .env, backups, etc.)
- Signal keywords: list any of these that apply:
  exposed_git, exposed_env, exposed_admin_panel, backup_file,
  missing_security_headers, cors_misconfiguration, login_endpoint
- A one-paragraph narrative summary for the analyst agent."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_scout(target: str) -> dict[str, Any]:
    """Run the Scout agent against target. Returns a HandoffEnvelope dict.

    The HandoffEnvelope is what crosses the boundary to the Analyst agent.
    It carries Scout's structured findings plus status signals so the Analyst
    can make informed tool decisions without re-running Scout's work.
    """
    logger.info("=== SCOUT STARTING | target: %s ===", target)

    try:
        agent_graph = create_react_agent(
            llm,
            SCOUT_TOOLS,
            prompt=SCOUT_SYSTEM_PROMPT,
        )

        result = agent_graph.invoke(
            {"messages": [("user", f"Target: {target}\nTask: Perform surface discovery on this target.")]},
            config={"recursion_limit": 15},
        )

        # -----------------------------------------------------------------------
        # Parse message history to extract structured data for the HandoffEnvelope
        # -----------------------------------------------------------------------
        findings: list[dict]     = []
        signal_candidates: set[str] = set()
        tools_used: list[str]    = []
        tech_stack: list[str]    = []
        discovered_paths: list[str] = []
        target_live: bool        = False
        status_code: int | None  = None

        for msg in result["messages"]:
            msg_type = type(msg).__name__

            if msg_type == "ToolMessage":
                tool_name = getattr(msg, "name", "unknown")
                tools_used.append(tool_name)

                try:
                    parsed = json.loads(msg.content)

                    # Aggregate findings and signals from every tool
                    for f in parsed.get("findings", []):
                        f["source_tool"] = tool_name
                        findings.append(f)
                    signal_candidates.update(parsed.get("signal_candidates", []))

                    # httpx-specific: pull live status and tech
                    if tool_name == "run_httpx":
                        if parsed.get("live") is True:
                            target_live = True
                        if parsed.get("status_code"):
                            status_code = parsed["status_code"]
                        tech_stack.extend(parsed.get("tech", []))
                        # Also check inside findings[0] (httpx packs it there)
                        for f in parsed.get("findings", []):
                            if isinstance(f, dict):
                                if f.get("live"):
                                    target_live = True
                                if f.get("status_code"):
                                    status_code = f["status_code"]
                                tech_stack.extend(f.get("tech", []))

                    # ffuf: extract discovered paths from findings
                    if tool_name == "run_ffuf":
                        for f in parsed.get("findings", []):
                            if isinstance(f, dict) and f.get("url"):
                                discovered_paths.append(f["url"])
                            elif isinstance(f, dict) and f.get("input"):
                                discovered_paths.append(f["input"])

                except (json.JSONDecodeError, AttributeError):
                    pass

        final_message = result["messages"][-1]
        scout_summary = getattr(final_message, "content", "") or ""

        envelope: dict[str, Any] = {
            "target":            target,
            "target_live":       target_live,
            "status_code":       status_code,
            "tech_stack":        sorted(set(tech_stack)),
            "discovered_paths":  discovered_paths,
            "signal_candidates": sorted(signal_candidates),
            "scout_summary":     scout_summary,
            "scout_tools_used":  list(dict.fromkeys(tools_used)),
            "scout_status":      "completed",
            "scout_error":       None,
        }
        logger.info("=== SCOUT COMPLETED | signals: %s ===", envelope["signal_candidates"])
        return envelope

    except Exception as exc:
        logger.exception("Scout agent failed")
        return {
            "target":            target,
            "target_live":       False,
            "status_code":       None,
            "tech_stack":        [],
            "discovered_paths":  [],
            "signal_candidates": [],
            "scout_summary":     "",
            "scout_tools_used":  [],
            "scout_status":      "failed",
            "scout_error":       str(exc),
        }
