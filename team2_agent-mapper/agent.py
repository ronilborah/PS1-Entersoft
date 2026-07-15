"""
agent.py — Mapper Agent ReAct Loop (v2)
LangGraph state machine with intent tracking, termination guard,
signal parsers, and action log for pipeline context passing.
Uses ChatOllama (native Ollama client) with Ollama Cloud support.
"""

import os
import json
import operator
from typing import Annotated, TypedDict
from dotenv import load_dotenv

from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langgraph.graph import StateGraph, END

from tools import TOOL_REGISTRY

load_dotenv()

# ---------------------------------------------------------------------------
# LLM — ChatOllama with Ollama Cloud support
# ---------------------------------------------------------------------------

llm = ChatOllama(
    model=os.getenv("OLLAMA_MODEL", "gpt-oss:120b-cloud"),
    base_url="https://ollama.com",
    client_kwargs={
        "headers": {
            "Authorization": f"Bearer {os.getenv('OLLAMA_API_KEY')}"
        }
    },
    temperature=0,
)

MAX_ITERATIONS = int(os.getenv("MAX_REACT_ITERATIONS", "8"))

# ---------------------------------------------------------------------------
# Agent State
# Travels through every node in the graph carrying all context
# ---------------------------------------------------------------------------

class AgentState(TypedDict):
    messages:   Annotated[list, operator.add]  # full conversation history
    target:     str                            # fixed for the run
    action_log: Annotated[list, operator.add]  # [{tool, intent, signals, detail}]
    iterations: int                            # loop counter
    finished:   bool                           # termination flag


# ---------------------------------------------------------------------------
# Signal Parsers
# Compress raw tool output into signal keywords before sending to LLM.
# Prevents context window overflow from large tool outputs.
# Keys match what her tools.py actually returns.
# ---------------------------------------------------------------------------

def parse_httpx(raw: dict) -> list[str]:
    signals = []
    if raw.get("live"):
        signals.append("tech_stack_detected")
    if raw.get("technologies") or raw.get("server"):
        signals.append("server_version_disclosed")
    return signals

def parse_katana(raw: dict) -> list[str]:
    signals = []
    urls = raw.get("urls", [])
    if any("swagger" in u or "api/docs" in u for u in urls):
        signals.append("swagger_openapi_found")
    if any("login" in u or "signin" in u for u in urls):
        signals.append("login_panel_discovered")
    if any("admin" in u for u in urls):
        signals.append("admin_route_exposed")
    if raw.get("total", 0) > 0:
        signals.append("unique_routes_found")
    return signals

def parse_naabu(raw: dict) -> list[str]:
    return ["open_ports_found"] if raw.get("open_ports") else []

def parse_jsluice(raw: dict) -> list[str]:
    signals = []
    if raw.get("endpoints"):
        signals.append("undocumented_api_in_js")
    if any("admin" in e for e in raw.get("endpoints", [])):
        signals.append("admin_route_exposed")
    if raw.get("secrets"):
        signals.append("secret_found_in_js")
    return signals

def parse_source_maps(raw: dict) -> list[str]:
    return ["source_map_found"] if raw.get("map_files_found") else []

def parse_gau(raw: dict) -> list[str]:
    return ["historical_urls_found"] if raw.get("total", 0) > 0 else []

def parse_waybackurls(raw: dict) -> list[str]:
    return ["wayback_urls_found"] if raw.get("total", 0) > 0 else []

def parse_dirsearch(raw: dict) -> list[str]:
    signals = []
    paths = raw.get("paths", [])
    if paths:
        signals.append("hidden_path_found")
    if any(p.get("path", "") in ["/.git", "/.env", "/config"] for p in paths):
        signals.append("sensitive_path_exposed")
    return signals

def parse_nirjas(raw: dict) -> list[str]:
    return ["developer_comments_found"] if raw.get("total", 0) > 0 else []

def parse_nmap(raw: dict) -> list[str]:
    return ["service_version_found"] if raw.get("services") else []

PARSERS = {
    "httpx":                  parse_httpx,
    "katana":                 parse_katana,
    "naabu":                  parse_naabu,
    "jsluice":                parse_jsluice,
    "source_maps_downloader": parse_source_maps,
    "gau":                    parse_gau,
    "waybackurls":            parse_waybackurls,
    "dirsearch":              parse_dirsearch,
    "nirjas":                 parse_nirjas,
    "nmap_service":           parse_nmap,
}

def run_and_parse(tool_name: str, target: str) -> tuple[str, list[str]]:
    """Run a tool and return (summary string, signals list)."""
    raw     = TOOL_REGISTRY[tool_name]().run(target)
    signals = PARSERS.get(tool_name, lambda r: [])(raw)
    result  = f"[{tool_name.upper()}] signals={signals} | data={json.dumps(raw)[:300]}"
    return result, signals


# ---------------------------------------------------------------------------
# LangChain Tools — what the LLM can call during the ReAct loop
# ---------------------------------------------------------------------------

def _make_tool(tool_name: str, description: str):
    @tool(tool_name, description=description)
    def _tool(target: str) -> str:
        result, _ = run_and_parse(tool_name, target)
        return result
    return _tool

run_naabu = _make_tool("run_naabu",
    "Fast port scanner. Discovers open TCP ports. Use when prompt mentions ports, services, or network exposure.")

run_nmap_service = _make_tool("run_nmap_service",
    "Service and version detection. Run after naabu to identify what is running on open ports.")

run_katana = _make_tool("run_katana",
    "Web crawler. Finds routes, endpoints, API paths, login panels, admin routes by walking the site.")

run_gau = _make_tool("run_gau",
    "GetAllUrls. Pulls historically known URLs from public archives. Finds forgotten or legacy endpoints.")

run_waybackurls = _make_tool("run_waybackurls",
    "Pulls historical URLs from Wayback Machine. Finds old endpoints, backup files, legacy API routes.")

run_dirsearch = _make_tool("run_dirsearch",
    "Directory brute-forcer. Finds hidden paths not discoverable by crawling — admin panels, backups, dot-files.")

run_jsluice = _make_tool("run_jsluice",
    "Extracts URLs and API endpoints from JavaScript files. Use when JS bundles are present.")

run_nirjas = _make_tool("run_nirjas",
    "Extracts developer comments from JS and source files. Reveals internal paths, TODOs, debug endpoints.")

run_source_maps_downloader = _make_tool("run_source_maps_downloader",
    "Detects and downloads exposed .map files. Source maps expose full original JS source code.")

MAPPER_TOOLS = [
    run_naabu, run_nmap_service, run_katana, run_gau,
    run_waybackurls, run_dirsearch, run_jsluice,
    run_nirjas, run_source_maps_downloader,
]

TOOL_NAME_MAP = {t.name: t for t in MAPPER_TOOLS}


# ---------------------------------------------------------------------------
# System Prompts
# ---------------------------------------------------------------------------

REACT_SYSTEM = """You are agent-mapper, a specialist security recon agent for F2 Surface Enumeration.

Your job: map the attack surface of a web target — endpoints, routes, JS files, API paths, open ports, hidden paths.

Available tools:
- run_naabu              → port scanning
- run_nmap_service       → service version detection (run after naabu)
- run_katana             → web crawling and route discovery
- run_gau                → historical URL discovery from archives
- run_waybackurls        → Wayback Machine URL history
- run_dirsearch          → hidden directory/file brute-forcing
- run_jsluice            → JavaScript endpoint and secret extraction
- run_nirjas             → developer comment extraction from JS
- run_source_maps_downloader → exposed source map detection

Rules:
1. httpx has already confirmed the target is live — do not run it again.
2. Choose tools based on the prompt and what signals each tool returns.
3. If a tool returns source_map_found, run run_jsluice next.
4. If a tool returns admin_route_exposed, note it and continue mapping.
5. Stop when you have covered the prompt scope — do not over-tool.
6. When done, say exactly: MAPPER_DONE
"""

SYNTHESIS_SYSTEM = """You are a security report writer for the Obsidia recon pipeline.

You will receive a list of tool actions taken by agent-mapper, each with:
- tool name
- intent (true = LLM chose deliberately, false = system-forced liveness check)
- signals found

Write a JSON object with exactly two fields:
- "summary": 2-3 sentences describing the attack surface, referencing specific signals
- "findings": list of objects, each with "tool", "intent", "signals", "detail"

Return only valid JSON. No markdown. No explanation outside the JSON.
"""


# ---------------------------------------------------------------------------
# Graph Nodes
# ---------------------------------------------------------------------------

def forced_httpx_node(state: AgentState) -> dict:
    """
    Node 1 — Always runs first, intent=False (system forced).
    Confirms liveness before giving LLM any control.
    """
    result, signals = run_and_parse("httpx", state["target"])
    log_entry = {
        "tool":    "httpx",
        "intent":  False,
        "signals": signals,
        "detail":  result,
    }
    return {
        "messages":   [HumanMessage(content=f"httpx liveness check complete: {result}")],
        "action_log": [log_entry],
    }


def llm_reason_node(state: AgentState) -> dict:
    """
    Node 2 — LLM reasoning step.
    Reads conversation so far, either calls a tool or says MAPPER_DONE.
    """
    bound_llm = llm.bind_tools(MAPPER_TOOLS)
    messages  = [SystemMessage(content=REACT_SYSTEM)] + state["messages"]
    response  = bound_llm.invoke(messages)
    finished  = isinstance(response.content, str) and "MAPPER_DONE" in response.content
    return {
        "messages":   [response],
        "iterations": state["iterations"] + 1,
        "finished":   finished,
    }


def tool_execution_node(state: AgentState) -> dict:
    """
    Node 3 — Executes the tool the LLM called.
    intent=True because LLM deliberately chose this.
    Enforces allowlist — blocks anything outside TOOL_NAME_MAP.
    """
    last_message = state["messages"][-1]
    new_messages = []
    new_log      = []

    if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
        return {"messages": [], "action_log": []}

    for tool_call in last_message.tool_calls:
        tool_name    = tool_call["name"]
        tool_args    = tool_call.get("args", {})
        target       = tool_args.get("target", state["target"])
        registry_key = tool_name.replace("run_", "", 1)

        if tool_name not in TOOL_NAME_MAP:
            result  = f"[BLOCKED] {tool_name} is not in agent-mapper's allowlist."
            signals = []
        else:
            result, signals = run_and_parse(registry_key, target)

        new_messages.append(
            ToolMessage(content=result, tool_call_id=tool_call["id"])
        )
        new_log.append({
            "tool":    tool_name,
            "intent":  True,
            "signals": signals,
            "detail":  result,
        })

    return {
        "messages":   new_messages,
        "action_log": new_log,
    }


def synthesize_node(state: AgentState) -> dict:
    """
    Node 4 — Separate LLM call acting as report writer.
    Reads full action_log and produces clean JSON summary.
    """
    log_text = json.dumps(state["action_log"], indent=2)
    prompt   = f"Here is the action log from agent-mapper:\n\n{log_text}\n\nWrite the JSON report."
    response = llm.invoke([
        SystemMessage(content=SYNTHESIS_SYSTEM),
        HumanMessage(content=prompt),
    ])
    return {"messages": [response]}


def _parse_synthesis_report(raw_output: object) -> tuple[str, list]:
    """Parse JSON report output, including repeatedly encoded model responses."""
    value = raw_output
    for _ in range(3):
        if not isinstance(value, str):
            break
        stripped = value.strip()
        if not stripped.startswith(("{", "[", '"')):
            break
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError:
            break
        if decoded == value:
            break
        value = decoded

    if not isinstance(value, dict):
        return str(value), []

    summary = value.get("summary", "")
    if isinstance(summary, str) and summary.strip().startswith("{"):
        try:
            inner = json.loads(summary.strip())
            if isinstance(inner, dict):
                value = inner
        except json.JSONDecodeError:
            pass

    findings = value.get("findings", [])
    if not isinstance(findings, list):
        findings = []
    return str(value.get("summary", "No summary returned.")), findings


# ---------------------------------------------------------------------------
# Termination Guard
# ---------------------------------------------------------------------------

def should_continue(state: AgentState) -> str:
    """
    Called after every LLM reasoning step.

    Will NOT stop if the only actions so far are intent=False (forced httpx).
    The LLM must make at least one deliberate tool call before stopping.
    """
    intentional_actions = [a for a in state["action_log"] if a["intent"] is True]

    # LLM wants to stop but hasn't done real work yet — override
    if state["finished"] and not intentional_actions:
        return "tools"

    if state["finished"]:
        return "synthesize"

    if state["iterations"] >= MAX_ITERATIONS:
        return "synthesize"

    last = state["messages"][-1]
    if hasattr(last, "tool_calls") and last.tool_calls:
        return "tools"

    return "synthesize"


# ---------------------------------------------------------------------------
# Build the LangGraph State Machine
# ---------------------------------------------------------------------------

def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("forced_httpx", forced_httpx_node)
    graph.add_node("llm_reason",   llm_reason_node)
    graph.add_node("tools",        tool_execution_node)
    graph.add_node("synthesize",   synthesize_node)

    graph.set_entry_point("forced_httpx")

    graph.add_edge("forced_httpx", "llm_reason")
    graph.add_conditional_edges("llm_reason", should_continue, {
        "tools":      "tools",
        "synthesize": "synthesize",
    })
    graph.add_edge("tools",     "llm_reason")
    graph.add_edge("synthesize", END)

    return graph.compile()

GRAPH = build_graph()


# ---------------------------------------------------------------------------
# Public Entry Point — called by main.py
# ---------------------------------------------------------------------------

def run_react_agent(prompt: str, target: str, context: dict) -> dict:
    """
    Run the full mapper ReAct loop for one task.
    Returns pipeline-contract dict with summary, findings, and action_log.
    """
    context_block = ""
    if context:
        context_block = f"\n\nUpstream Scout context:\n{json.dumps(context, indent=2)}"

    initial_message = HumanMessage(content=(
        f"Task: {prompt}\n"
        f"Target: {target}"
        f"{context_block}\n\n"
        f"Map the attack surface. When done, say MAPPER_DONE."
    ))

    initial_state: AgentState = {
        "messages":   [initial_message],
        "target":     target,
        "action_log": [],
        "iterations": 0,
        "finished":   False,
    }

    try:
        final_state = GRAPH.invoke(initial_state)
        raw_output  = final_state["messages"][-1].content

        summary, findings = _parse_synthesis_report(raw_output)

        return {
            "agent_id": "agent-mapper",
            "status":   "completed",
            "response": {
                "summary":    summary,
                "findings":   findings,
                "action_log": final_state["action_log"],
            }
        }

    except Exception as exc:
        return {
            "agent_id": "agent-mapper",
            "status":   "failed",
            "response": {"error": str(exc)},
        }


# Keep MAPPER_TOOLS exported for main.py import
__all__ = ["run_react_agent", "MAPPER_TOOLS"]
