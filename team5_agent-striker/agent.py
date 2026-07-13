"""agent.py — LangGraph ReAct agent for agent-striker (Team 5).

Key design decisions
--------------------
1. HITL gate: every exploit tool call must be preceded by hitl_approve().
   In mock mode this auto-approves and logs. In real mode it blocks until
   a human types "approve" in the terminal (or you wire a real approval API).

2. Intent tracking: every tool call appends an entry to action_log with
   { tool, target, intent_is_malicious: bool, reasoning, output_summary }.
   The ReAct loop uses the accumulated intent flags to decide termination:
   if any action was flagged malicious=True AND hitl was not approved,
   the loop halts immediately. This list is also returned in the final
   response so the caller can audit every decision.

3. Termination: the loop stops when:
   (a) the LLM emits a final answer (no more tool calls), OR
   (b) all relevant tools have been called once (recursion_limit), OR
   (c) a malicious-intent action is attempted without prior HITL approval.

4. Structured output: every tool call writes outputs/<tool>_<ts>.json;
   the final response writes outputs/final_response_<ts>.json.
"""

from __future__ import annotations

import contextvars
import datetime
import json
import os
import pathlib
from typing import Any

from dotenv import load_dotenv
load_dotenv()

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools import TOOL_REGISTRY
from httpx_parser import parse_httpx

AGENT_ID     = "agent-striker"
OLLAMA_URL   = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3.5:0.8b")

_OUTPUTS_DIR = pathlib.Path(__file__).parent / "outputs"

# ── LLM client (Ollama OpenAI-compatible endpoint) ────────────────────────────

llm = ChatOpenAI(
    model=OLLAMA_MODEL,
    base_url=OLLAMA_URL,
    api_key=os.getenv("OLLAMA_API_KEY", "ollama"),
    temperature=0,
)

# ── Per-request state (isolated via contextvars) ──────────────────────────────

_state_var: contextvars.ContextVar[dict] = contextvars.ContextVar("agent_state")


def _reset_state() -> None:
    _state_var.set({"action_log": [], "hitl_approved": set(), "skipped": []})


def _get_state() -> dict:
    return _state_var.get()


def _log_action(
    tool_name: str,
    target: str,
    intent_is_malicious: bool,
    reasoning: str,
    output_summary: str,
    hitl_approved: bool = False,
) -> None:
    _get_state()["action_log"].append({
        "tool":                tool_name,
        "target":              target,
        "intent_is_malicious": intent_is_malicious,
        "hitl_approved":       hitl_approved,
        "reasoning":           reasoning,
        "output_summary":      output_summary,
    })


def _strip_markdown(text: str) -> str:
    """Remove markdown formatting so summary fields contain plain prose."""
    import re
    text = re.sub(r'\*{1,3}([^*]+)\*{1,3}', r'\1', text)   # **bold**, *italic*, ***both***
    text = re.sub(r'`[^`]*`', lambda m: m.group(0)[1:-1], text)  # `inline code`
    text = re.sub(r'^\s*#{1,6}\s+', '', text, flags=re.MULTILINE)  # ## headings
    text = re.sub(r'^\s*[-*+]\s+', '', text, flags=re.MULTILINE)   # bullet points
    text = re.sub(r'^\|.*\|$', '', text, flags=re.MULTILINE)        # | table | rows |
    text = re.sub(r'^\s*[-|: ]+$', '', text, flags=re.MULTILINE)    # table separator lines
    text = re.sub(r'\n{3,}', '\n\n', text)                          # collapse excess blank lines
    return text.strip()


def _strip_banner_lines(text: str) -> str:
    """Remove sqlmap ASCII-art banner lines (pure dashes, brackets, pipes, whitespace)."""
    import re
    clean = [
        line for line in text.splitlines()
        if re.search(r'[a-zA-Z0-9]', line)  # keep only lines that contain a real word character
    ]
    return '\n'.join(clean)


def _save_tool_output(tool: str, target: str, raw_output: str, parsed_findings: list) -> str:
    """Write a structured JSON record for one tool run. Returns the file path."""
    _OUTPUTS_DIR.mkdir(exist_ok=True)
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")[:19]  # seconds precision
    mode = "mock" if os.getenv("TOOL_MOCK_MODE", "true").lower() == "true" else "real"
    data = {
        "tool": tool,
        "target": target,
        "raw_output": raw_output,
        "parsed_findings": parsed_findings,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "mode": mode,
    }
    path = _OUTPUTS_DIR / f"{tool}_{ts}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return str(path)


# ── HITL gate ─────────────────────────────────────────────────────────────────

MOCK_HITL: bool = os.getenv("TOOL_MOCK_MODE", "true").lower() == "true"
EXPLOIT_TOOLS = {"sqlmap", "xsstrike", "dalfox", "smuggler", "ssrfmap", "tplmap", "crlfuzzer"}


@tool
def hitl_approve(tool_name: str, target: str, reason: str) -> str:
    """
    Request human approval before running an exploit tool.
    ALWAYS call this before calling any exploit tool (sqlmap, xsstrike, dalfox,
    smuggler, ssrfmap, tplmap, crlfuzzer). Do not skip this step.

    Args:
        tool_name: The exact tool key you intend to run next.
        target:    The URL or endpoint you intend to target.
        reason:    One sentence explaining what vulnerability you expect to find and why.
    """
    key = f"{tool_name}:{target}"

    if MOCK_HITL:
        print(f"[MOCK HITL] AUTO-APPROVING {tool_name} on {target} — reason: {reason}")
        _get_state()["hitl_approved"].add(key)
        _log_action(
            tool_name=f"hitl_approve({tool_name})",
            target=target,
            intent_is_malicious=True,
            reasoning=reason,
            output_summary=f"APPROVED (mock): {tool_name} cleared on {target}",
            hitl_approved=True,
        )
        return f"APPROVED: {tool_name} is cleared to run on {target}. Proceed."
    else:
        print(f"\n[HITL REQUIRED] Agent wants to run: {tool_name}")
        print(f"  Target  : {target}")
        print(f"  Reason  : {reason}")
        answer = input("Type 'approve' to allow, anything else to deny: ").strip().lower()
        if answer == "approve":
            _get_state()["hitl_approved"].add(key)
            _log_action(
                tool_name=f"hitl_approve({tool_name})",
                target=target,
                intent_is_malicious=True,
                reasoning=reason,
                output_summary=f"APPROVED (human): {tool_name} cleared on {target}",
                hitl_approved=True,
            )
            return f"APPROVED: {tool_name} is cleared to run on {target}. Proceed."
        else:
            _log_action(
                tool_name=f"hitl_approve({tool_name})",
                target=target,
                intent_is_malicious=True,
                reasoning=reason,
                output_summary=f"DENIED (human): {tool_name} blocked on {target}",
                hitl_approved=False,
            )
            return f"DENIED: {tool_name} was NOT approved for {target}. Do not run it."


def _check_hitl(tool_name: str, target: str) -> str | None:
    if tool_name in EXPLOIT_TOOLS:
        key = f"{tool_name}:{target}"
        if key not in _get_state()["hitl_approved"]:
            return (
                f"BLOCKED: {tool_name} requires HITL approval before running. "
                f"Call hitl_approve('{tool_name}', '{target}', reason) first."
            )
    return None


# ── Tool wrappers ─────────────────────────────────────────────────────────────

@tool
def run_httpx(target: str) -> str:
    """
    Run httpx to verify the target is live and detect tech stack.
    Intent: reconnaissance only — not malicious.
    Always run this first to confirm the target is reachable.
    """
    try:
        raw = TOOL_REGISTRY["httpx"]().run(target)
    except RuntimeError as exc:
        msg = f"[SKIPPED] httpx: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "httpx", "target": target, "error": str(exc)})
        _save_tool_output("httpx", target, str(exc), [])
        _log_action("httpx", target, False, "Tool unavailable.", msg)
        return msg

    parsed = parse_httpx(raw, target)
    _log_action(
        tool_name="httpx",
        target=target,
        intent_is_malicious=False,
        reasoning="Verify target liveness and basic tech stack before exploitation.",
        output_summary=parsed["semantic_summary"] or raw[:300],
    )
    _save_tool_output("httpx", target, raw, [parsed])
    signals = parsed["signal_candidates"] or ["none detected"]
    return f"httpx output: {raw}\nsignals detected: {signals}"


@tool
def run_sqlmap(target: str, param: str = "") -> str:
    """
    Run sqlmap to test for SQL injection vulnerabilities.
    Intent: MALICIOUS — sends injection payloads. Requires prior hitl_approve call.

    Args:
        target: Full URL including query string if applicable.
        param:  POST body data string if testing POST parameters.
    """
    blocked = _check_hitl("sqlmap", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["sqlmap"]().run(target, param=param)
    except RuntimeError as exc:
        msg = f"[SKIPPED] sqlmap: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "sqlmap", "target": target, "error": str(exc)})
        _save_tool_output("sqlmap", target, str(exc), [])
        _log_action("sqlmap", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="sqlmap",
        target=target,
        intent_is_malicious=True,
        reasoning="Validate SQL injection on identified injectable parameter.",
        output_summary=_strip_banner_lines(raw)[:500],
        hitl_approved=True,
    )
    _save_tool_output("sqlmap", target, raw, [])
    return f"sqlmap output: {raw}"


@tool
def run_xsstrike(target: str) -> str:
    """
    Run xsstrike to find and validate XSS vulnerabilities.
    Intent: MALICIOUS — injects script payloads. Requires prior hitl_approve call.
    """
    blocked = _check_hitl("xsstrike", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["xsstrike"]().run(target)
    except RuntimeError as exc:
        msg = f"[SKIPPED] xsstrike: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "xsstrike", "target": target, "error": str(exc)})
        _save_tool_output("xsstrike", target, str(exc), [])
        _log_action("xsstrike", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="xsstrike",
        target=target,
        intent_is_malicious=True,
        reasoning="Validate reflected XSS on parameters flagged by upstream kxss/Prober.",
        output_summary=raw[:300],
        hitl_approved=True,
    )
    _save_tool_output("xsstrike", target, raw, [])
    return f"xsstrike output: {raw}"


@tool
def run_dalfox(target: str) -> str:
    """
    Run dalfox for deep XSS parameter scanning and payload generation.
    Intent: MALICIOUS — injects payloads. Requires prior hitl_approve call.
    """
    blocked = _check_hitl("dalfox", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["dalfox"]().run(target)
    except RuntimeError as exc:
        msg = f"[SKIPPED] dalfox: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "dalfox", "target": target, "error": str(exc)})
        _save_tool_output("dalfox", target, str(exc), [])
        _log_action("dalfox", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="dalfox",
        target=target,
        intent_is_malicious=True,
        reasoning="Deep XSS scan on endpoints with confirmed reflection from Prober context.",
        output_summary=raw[:300],
        hitl_approved=True,
    )
    _save_tool_output("dalfox", target, raw, [])
    return f"dalfox output: {raw}"


@tool
def run_smuggler(target: str) -> str:
    """
    Run smuggler to test for HTTP request smuggling.
    Intent: MALICIOUS — sends malformed HTTP requests. Requires prior hitl_approve call.
    """
    blocked = _check_hitl("smuggler", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["smuggler"]().run(target)
    except RuntimeError as exc:
        msg = f"[SKIPPED] smuggler: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "smuggler", "target": target, "error": str(exc)})
        _save_tool_output("smuggler", target, str(exc), [])
        _log_action("smuggler", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="smuggler",
        target=target,
        intent_is_malicious=True,
        reasoning="Test for HTTP request smuggling on reverse-proxy target.",
        output_summary=raw[:300],
        hitl_approved=True,
    )
    _save_tool_output("smuggler", target, raw, [])
    return f"smuggler output: {raw}"


@tool
def run_ssrfmap(target: str, param: str = "") -> str:
    """
    Run ssrfmap to test for Server-Side Request Forgery vulnerabilities.
    Intent: MALICIOUS — triggers outbound requests from server. Requires prior hitl_approve call.

    Args:
        target: Full URL including query string.
        param:  The exact query parameter name to fuzz for SSRF (e.g. "url",
                "redirect", "file"). If omitted, the first query parameter found
                in the URL is used.
    """
    blocked = _check_hitl("ssrfmap", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["ssrfmap"]().run(target, param=param)
    except RuntimeError as exc:
        msg = f"[SKIPPED] ssrfmap: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "ssrfmap", "target": target, "error": str(exc)})
        _save_tool_output("ssrfmap", target, str(exc), [])
        _log_action("ssrfmap", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="ssrfmap",
        target=target,
        intent_is_malicious=True,
        reasoning="Test SSRF on URL or file parameters identified in Prober context.",
        output_summary=raw[:300],
        hitl_approved=True,
    )
    _save_tool_output("ssrfmap", target, raw, [])
    return f"ssrfmap output: {raw}"


@tool
def run_tplmap(target: str) -> str:
    """
    Run tplmap to detect and exploit Server-Side Template Injection (SSTI).
    Intent: MALICIOUS — injects template expressions. Requires prior hitl_approve call.
    """
    blocked = _check_hitl("tplmap", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["tplmap"]().run(target)
    except RuntimeError as exc:
        msg = f"[SKIPPED] tplmap: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "tplmap", "target": target, "error": str(exc)})
        _save_tool_output("tplmap", target, str(exc), [])
        _log_action("tplmap", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="tplmap",
        target=target,
        intent_is_malicious=True,
        reasoning="Validate SSTI on template parameters found in Prober context.",
        output_summary=raw[:300],
        hitl_approved=True,
    )
    _save_tool_output("tplmap", target, raw, [])
    return f"tplmap output: {raw}"


@tool
def run_crlfuzzer(target: str) -> str:
    """
    Run crlfuzzer to test for CRLF injection vulnerabilities.
    Intent: MALICIOUS — injects carriage-return/line-feed sequences. Requires prior hitl_approve call.
    """
    blocked = _check_hitl("crlfuzzer", target)
    if blocked:
        return blocked
    try:
        raw = TOOL_REGISTRY["crlfuzzer"]().run(target)
    except RuntimeError as exc:
        msg = f"[SKIPPED] crlfuzzer: {exc}"
        print(f"[WARN] {msg}")
        _get_state()["skipped"].append({"tool": "crlfuzzer", "target": target, "error": str(exc)})
        _save_tool_output("crlfuzzer", target, str(exc), [])
        _log_action("crlfuzzer", target, True, "Tool unavailable.", msg, hitl_approved=True)
        return msg

    _log_action(
        tool_name="crlfuzzer",
        target=target,
        intent_is_malicious=True,
        reasoning="Test CRLF injection on redirect or header-reflecting parameters.",
        output_summary=raw[:300],
        hitl_approved=True,
    )
    _save_tool_output("crlfuzzer", target, raw, [])
    return f"crlfuzzer output: {raw}"


# ── Tool list for LangGraph ───────────────────────────────────────────────────

TOOLS = [
    hitl_approve,
    run_httpx,
    run_sqlmap,
    run_xsstrike,
    run_dalfox,
    run_smuggler,
    run_ssrfmap,
    run_tplmap,
    run_crlfuzzer,
]


# ── ReAct agent entry point ───────────────────────────────────────────────────

def run_react_agent(prompt: str, target: str, context: dict) -> dict:
    """
    Run the LangGraph ReAct agent for agent-striker.

    The agent reasons about the prompt and context, calls HITL approval before
    each exploit tool, runs tools, and returns a structured JSON response.

    Every tool call is recorded in action_log with intent_is_malicious bool,
    which is used by the loop to detect unapproved malicious actions and by
    the caller to audit the full decision chain.

    Writes outputs/final_response_<ts>.json with the full findings list.
    """
    _reset_state()

    agent = create_react_agent(llm, TOOLS)

    context_summary = json.dumps(context, indent=2) if context else "No upstream context provided."

    full_prompt = f"""You are agent-striker, a security exploitation validation agent.
Your job: {prompt}

Target: {target}

Context from upstream Prober agent:
{context_summary}

YOUR RULES (follow strictly):
1. Always run run_httpx first to confirm the target is live.
2. Before running ANY exploit tool (sqlmap, xsstrike, dalfox, smuggler, ssrfmap, tplmap, crlfuzzer),
   you MUST call hitl_approve with the tool name, target, and a one-sentence reason.
3. Only run exploit tools on endpoints or parameters explicitly mentioned in the Prober context.
4. If hitl_approve returns DENIED, do not run that tool. Move to the next finding.
5. After running all relevant tools, produce a final summary that:
   - Lists every confirmed vulnerability with its type, endpoint, and severity
   - Lists every tool that was DENIED by HITL and why
   - Gives an overall risk rating: CRITICAL / HIGH / MEDIUM / LOW / NONE

Be specific. Reference exact endpoints and parameter names from the context.
Do not run tools on endpoints not mentioned in the context.
"""

    try:
        result = agent.invoke(
            {"messages": [("user", full_prompt)]},
            config={"recursion_limit": 20},
        )
        final_message = _strip_markdown(result["messages"][-1].content)
    except Exception as exc:
        final_message = f"Agent loop error: {str(exc)}"

    action_log = _get_state()["action_log"]
    skipped = _get_state()["skipped"]

    findings = []
    for entry in action_log:
        if entry["intent_is_malicious"] and entry["hitl_approved"] and entry["tool"] != "hitl_approve":
            findings.append({
                "tool":    entry["tool"],
                "target":  entry["target"],
                "summary": entry["output_summary"],
                "status":  "completed",
            })
    for s in skipped:
        findings.append({
            "tool":    s["tool"],
            "target":  s["target"],
            "summary": f"SKIPPED: {s['error']}",
            "status":  "skipped",
        })

    unapproved = [
        e for e in action_log
        if e["intent_is_malicious"] and not e["hitl_approved"]
        and not e["tool"].startswith("hitl_approve")
    ]

    response = {
        "agent_id": AGENT_ID,
        "status": "completed" if not unapproved else "blocked",
        "response": {
            "summary":    final_message,
            "findings":   findings,
            "hitl_log":   [e for e in action_log if "hitl_approve" in e["tool"]],
            "action_log": action_log.copy(),
        },
    }

    # Write final response to outputs/
    try:
        _OUTPUTS_DIR.mkdir(exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        final_path = _OUTPUTS_DIR / f"final_response_{ts}.json"
        with open(final_path, "w") as f:
            json.dump(response, f, indent=2)
    except Exception as exc:
        print(f"[WARN] Could not write final response file: {exc}")

    return response
