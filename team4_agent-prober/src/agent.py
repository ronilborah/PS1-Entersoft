"""agent.py

LangGraph ReAct agent for agent-prober (Team 4 — F4 Active Scan, safe tier).

WHAT THIS REPLACES
------------------
planner.py was a fixed keyword rulebook: if "tls" in prompt -> run testssl_deep.
That is called an automation — the tool order is decided at write time by a
human, and cannot change based on what the tools actually find.

This file replaces that with an agent: an LLM (Ollama, accessed via its
OpenAI-compatible endpoint) that reads the prompt, picks a tool, reads that
tool's output, then decides whether to run another tool or stop. The LLM
reasons at runtime, not a human-written rulebook at write time.

REACT LOOP (how the LLM thinks)
---------------------------------
The LLM goes through this cycle until it decides it has enough to answer:

  Thought:     "I need to check TLS first because the prompt mentions ciphers."
  Intent:      "Check whether weak TLS protocols are offered on this server."
  Action:      run_testssl_deep(target="https://target.com")
  Observation: {"findings": [{"id": "TLS1", "finding": "TLS 1.0 offered"}], ...}
  Fulfilled:   True
  Thought:     "TLS 1.0 is weak. I should also check for general misconfigs."
  Intent:      "Run general misconfiguration templates across the target."
  Action:      run_nuclei_active(target="https://target.com")
  Observation: {"findings": [], ...}
  Fulfilled:   True
  Thought:     "Nothing else relevant. I have enough to summarise."
  Final answer: "Target exposes TLS 1.0 (weak cipher suite)..."

INTENT TRACKING
---------------
Before every tool call the LLM writes:
  Intent: [one sentence — what specific question this tool call is trying to answer]
  Fulfilled: [True/False — did the PREVIOUS tool call answer its intent]

These are parsed from the message history and returned as intent_log in the
response. This makes the agent's reasoning auditable and feeds into termination
— if all intents are fulfilled the agent has been successfully answering its
own questions.

LANGGRAPH
---------
LangGraph is a library that structures the ReAct loop as a state machine.
create_react_agent() is a prebuilt function that wires up the full
Thought->Action->Observation->Thought->... graph for you, including the
stopping condition (when the LLM produces a plain text answer with no tool
call, LangGraph recognises that as "done" and exits the loop).

OLLAMA / OPENAI-COMPATIBLE ENDPOINT
-------------------------------------
Ollama runs a language model locally (or on a shared server). It exposes the
exact same HTTP API format as OpenAI, so the openai Python client works
unchanged — you just change base_url to point at Ollama instead of OpenAI.
api_key="ollama" is a placeholder; Ollama doesn't validate it, but the
client library requires some string to be present.
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import json
import logging
import os
import re
from typing import Any

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools import MOCK_MODE, get_tool

logger = logging.getLogger("agent-prober")

# ---------------------------------------------------------------------------
# LLM setup — points at Ollama's OpenAI-compatible endpoint.
# Override via env vars (set in .env or shell):
#   OLLAMA_BASE_URL=http://localhost:11434/v1
#   OLLAMA_MODEL=qwen2.5:7b
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")

# temperature=0 means the LLM always picks the most likely next token —
# no randomness, which is what you want for a reasoning agent.
# The LLM should make deterministic tool choices, not creative ones.
llm = ChatOpenAI(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_BASE_URL,
    api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
    temperature=0,
)
# ---------------------------------------------------------------------------
# Tool definitions for LangGraph.
#
# Each @tool function is a wrapper around one entry in your TOOL_REGISTRY.
# LangGraph exposes these to the LLM. The LLM sees the function name and its
# docstring and decides when (if ever) to call it. The docstring IS the
# LLM's only description of what the tool does — so they need to be specific
# and accurate, not generic.
#
# Every tool returns a string, because that is what LangGraph passes back to
# the LLM as the "Observation" step. We serialise the structured dict to a
# compact JSON string so the LLM can read it as text.
# ---------------------------------------------------------------------------

def _run(tool_key: str, target: str, context: dict | None = None) -> str:
    """Helper: run one tool and return its output as a compact JSON string."""
    logger.info(">>> TOOL CALLED: %s | target: %s", tool_key, target)
    try:
        result = get_tool(tool_key).run(target, context or {})
        # Compact JSON keeps the output small enough to fit in the context window.
        # The LLM reads this as the Observation step of its ReAct cycle.
        return json.dumps({
            "signal_candidates": result.get("signal_candidates", []),
            "findings": result.get("findings", [])[:10],  # cap at 10 findings
            "errors": result.get("errors", []),
            "mock": result.get("mock", True),
        }, indent=2)
    except PermissionError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        return json.dumps({"error": f"{tool_key} raised {type(exc).__name__}: {exc}"})


@tool
def run_httpx(target: str) -> str:
    """Check if the target URL is live, get its HTTP status code, page title,
    and detected technologies (web server, framework, CMS hints).
    Always run this first to confirm the target is reachable."""
    return _run("httpx", target)


@tool
def run_nuclei_active(target: str) -> str:
    """Run nuclei active scan templates (http/vulnerabilities and
    http/misconfiguration) against the target. Finds missing security headers,
    exposed configs, known CVE matches, and other active misconfigurations.
    Good general-purpose first active scan."""
    return _run("nuclei_active", target)


@tool
def run_testssl_deep(target: str) -> str:
    """Run a deep TLS/SSL analysis on the target. Checks for weak protocol
    versions (TLS 1.0, TLS 1.1, SSLv3), vulnerable cipher suites, and known
    TLS vulnerabilities (BREACH, BEAST, LUCKY13, POODLE). Use when the prompt
    mentions TLS, SSL, ciphers, certificates, or HTTPS security."""
    return _run("testssl_deep", target)


@tool
def run_ffuf(target: str) -> str:
    """Fuzz the target for hidden directories, backup files, admin panels, and
    sensitive paths using a wordlist. Returns discovered paths with their HTTP
    status codes. Use when the prompt mentions directory fuzzing, hidden paths,
    backup files, or content discovery."""
    return _run("ffuf", target)


@tool
def run_kxss(target: str) -> str:
    """Test the target URL for reflected XSS by checking which special
    characters (quotes, angle brackets, etc.) are returned unfiltered in the
    response. Use when the prompt mentions reflected XSS, parameter reflection,
    or XSS testing on a specific URL with parameters."""
    return _run("kxss", target)


@tool
def run_corsy(target: str) -> str:
    """Test the target for CORS misconfigurations — checks whether the server
    reflects arbitrary origins or whitelists null, which would allow a
    malicious site to read authenticated responses. Use when the prompt
    mentions CORS, cross-origin, or Access-Control headers."""
    return _run("corsy", target)


@tool
def run_nikto(target: str) -> str:
    """Run nikto web server scanner for known misconfigurations, dangerous
    files, outdated software banners, and missing security headers. Broad
    general scan — use when no more specific tool fits, or the prompt asks
    for a general web server check."""
    return _run("nikto", target)


@tool
def run_wpscan_full(target: str) -> str:
    """Run a full wpscan enumeration against a WordPress site: core version
    vulnerabilities, plugin vulnerabilities, theme vulnerabilities, and user
    enumeration. Use only when the target is confirmed or suspected to be
    WordPress."""
    return _run("wpscan_full", target)


@tool
def run_droopescan(target: str) -> str:
    """Run droopescan against the target to detect CMS type and version
    (Drupal, SilverStripe, Joomla, Moodle, WordPress). Use when the prompt
    mentions Drupal, droopescan, or CMS version detection."""
    return _run("droopescan", target)


# wfuzz deliberately excluded — confirmed broken on Python 3.12 (imp module
# removed), and ffuf covers the same fuzzing capability.

AGENT_TOOLS = [
    run_httpx,
    run_nuclei_active,
    run_testssl_deep,
    run_ffuf,
    run_kxss,
    run_corsy,
    run_nikto,
    run_wpscan_full,
    run_droopescan,
]


# ---------------------------------------------------------------------------
# System prompt — the standing instructions the LLM reads before every task.
# This is not the user's prompt. This is the "you are a security agent, here
# are your rules" part that frames the entire conversation.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are agent-prober, a specialist security recon agent responsible for
F4 active scanning (safe tier — no exploit tools).

Your allowed tools: run_httpx, run_nuclei_active, run_testssl_deep, run_ffuf,
run_kxss, run_corsy, run_nikto, run_wpscan_full, run_droopescan.

Rules:
- Always run run_httpx first to confirm the target is live before running any
  other tool. If the target is not live, stop immediately and report that.
- Pick tools based on what the prompt asks for AND what previous tool outputs
  reveal. Do not run tools whose output would be irrelevant.
- Stop when you have enough to answer — do not run every tool by default.
- Keep tool calls to a maximum of 5 per task to avoid timeout.

Before EVERY tool call, you must write your reasoning in this exact format:
Thought: [what you observed from the previous tool, and what security conclusion you draw]
Intent: [one sentence — what specific question this next tool call is trying to answer]
Fulfilled: [True or False — did the PREVIOUS tool call answer its intent? Write N/A for the first tool]

After running tools, write a clear summary that mentions specific signals
found. Do not write generic summaries that could apply to any target."""


# ---------------------------------------------------------------------------
# Public entry point — called by main.py instead of select_tools()
# ---------------------------------------------------------------------------

def run_react_agent(prompt: str, target: str, context: dict[str, Any]) -> dict[str, Any]:
    """Run the ReAct agent for one task. Returns the standard API response dict.

    This replaces the old pattern of:
        tool_keys = select_tools(prompt, context)
        for key in tool_keys: get_tool(key).run(target)

    Instead the LLM decides which tools to call and in what order, reading
    each tool's output before deciding what to do next.
    """

    context_block = ""
    if context:
        context_block = f"\nUpstream context from previous agents:\n{json.dumps(context, indent=2)}\n"

    full_prompt = (
        f"Target: {target}\n"
        f"Task: {prompt}"
        f"{context_block}"
    )

    try:
        # create_react_agent wires up the full Thought->Action->Observation
        # loop as a LangGraph state machine graph. We pass it the LLM and the
        # list of tools. It returns a graph object we can invoke.
        agent_graph = create_react_agent(
            llm,
            AGENT_TOOLS,
            prompt=SYSTEM_PROMPT,
        )

        # recursion_limit caps how many Thought->Action->Observation cycles
        # the graph will allow before stopping regardless of what the LLM wants.
        # This prevents infinite loops where the LLM keeps calling tools forever.
        result = agent_graph.invoke(
            {"messages": [("user", full_prompt)]},
            config={"recursion_limit": 20},
        )

        # -----------------------------------------------------------------------
        # Extract findings, signals, and intent log from the message history.
        #
        # LangGraph accumulates all messages in result["messages"]:
        #   HumanMessage       — the original prompt
        #   AIMessage          — LLM response (either a tool call or final answer)
        #                        may contain Thought/Intent/Fulfilled lines
        #   ToolMessage        — the output of a tool call (the Observation step)
        #   ... repeating ...
        #   AIMessage (final)  — plain text, no tool call — the written summary
        #
        # We parse Intent: and Fulfilled: lines from AIMessages, and collect
        # findings/signals from ToolMessages.
        # -----------------------------------------------------------------------

        findings: list[dict] = []
        signal_candidates: set[str] = set()
        tools_used: list[str] = []
        intent_log: list[dict] = []

        current_intent = "N/A"

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
                            # attach fulfilled status to the previous tool entry
                            intent_log[-1]["fulfilled"] = fulfilled_str == "True"

            if msg_type == "ToolMessage":
                tool_name = getattr(msg, "name", "unknown")
                tools_used.append(tool_name)

                intent_log.append({
                    "tool": tool_name,
                    "intent": current_intent,
                    "fulfilled": None,  # filled in when next AIMessage arrives
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

        # The last tool never gets a subsequent AIMessage with Fulfilled:
        # because the LLM writes its final answer instead.
        # We mark it True — the agent chose to stop after it, meaning it
        # considered that intent satisfied.
        if intent_log and intent_log[-1]["fulfilled"] is None:
            intent_log[-1]["fulfilled"] = True

        specific_endpoints: list[str] = []
        for entry in findings:
            source_tool = entry.get("source_tool")
            if source_tool == "run_ffuf":
                if entry.get("status") in (200, 301, 302, 403) and entry.get("url"):
                    specific_endpoints.append(entry["url"])
            elif source_tool == "run_nuclei_active":
                if entry.get("matched_at"):
                    specific_endpoints.append(entry["matched_at"])
            elif source_tool == "run_nikto":
                finding = entry.get("finding")
                if isinstance(finding, str):
                    specific_endpoints.extend(
                        url.rstrip(".,;:)]}")
                        for url in re.findall(r"https?://[^\s\"'<>]+", finding)
                    )
        specific_endpoints = list(dict.fromkeys(specific_endpoints))

        return {
            "agent_id": "agent-prober",
            "status": "completed",
            "response": {
                "summary": result["messages"][-1].content,
                "findings": [
                    {
                        "signal_candidates": sorted(signal_candidates),
                        "tools_used": list(dict.fromkeys(tools_used)),
                        "tool_errors": [],
                        "intent_log": intent_log,
                        "details": findings,
                    }
                ],
                "specific_endpoints": specific_endpoints,
            },
        }

    except Exception as exc:
        logger.exception("ReAct agent failed")
        return {
            "agent_id": "agent-prober",
            "status": "failed",
            "response": {},
            "error": str(exc),
        }
