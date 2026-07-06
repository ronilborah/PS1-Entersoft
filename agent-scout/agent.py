"""
agent.py
--------
LangGraph ReAct agent for Scout (Team 1, F1 Fingerprinting).

Replaces selector.py + the manual tool loop from main.py v1.

The LLM (Ollama via OpenAI-compatible endpoint) reads the prompt, decides
which Scout tools are relevant, calls them, reads each tool's structured
signal output, and reasons about what to do next. It stops when it has
enough to write a final answer, or when it has run all relevant tools.

Entry point: run_react_agent(prompt, target, context) → called by main.py.

Env vars (loaded from .env):
    TOOL_MOCK_MODE    — true|false (controls tool execution, not LLM)
    OLLAMA_BASE_URL   — Ollama endpoint, default http://localhost:11434/v1
    OLLAMA_MODEL      — model name, default llama3
"""

import json
import os

from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools import TOOL_REGISTRY
from parsers.httpx_parser import parse_httpx

load_dotenv()

AGENT_ID = "agent-scout"


# ---------------------------------------------------------------------------
# LLM — Ollama via OpenAI-compatible endpoint
# ---------------------------------------------------------------------------

_llm = ChatOpenAI(
    model=os.getenv("OLLAMA_MODEL", "llama3"),
    base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
    api_key=os.getenv("OLLAMA_API_KEY", "ollama"),  # Ollama ignores this; the client requires it
    temperature=0,          # deterministic = better for security reasoning
)


# ---------------------------------------------------------------------------
# Helper: safely extract text from a tool result in both mock and real mode.
#
# Mock mode → result is a structured dict with named keys (alive, tech_stack…)
# Real mode → result is {"ok": bool, "raw": "<CLI output text>", "mode":"real"}
#
# Callers use _real_text() when they need the raw text string, and
# _safe_get() when they need a specific field that exists in mock mode only.
# ---------------------------------------------------------------------------

def _safe_get(result: dict, key: str, fallback: str = "unknown") -> str:
    """Return a field from result, or fallback gracefully in real mode."""
    value = result.get(key)
    if value is not None:
        return str(value)
    # real mode: the data is in .raw, not in named fields
    if result.get("mode") == "real":
        raw_text = result.get("raw", "")
        if raw_text:
            return f"(real mode — see raw output: {raw_text[:300]})"
    return fallback


def _ok(result: dict) -> bool:
    """Return True if the tool ran without error, in either mode."""
    if result.get("mode") == "mock":
        return True  # mock never fails structurally
    return bool(result.get("ok"))


# ---------------------------------------------------------------------------
# @tool wrappers — one per Scout allowlist entry
#
# The docstring is what the LLM reads to decide whether to call this tool.
# Keep it specific: what the tool detects and when to use it.
# ---------------------------------------------------------------------------

@tool
def run_httpx(target: str) -> str:
    """
    Run httpx against the target to confirm liveness, HTTP status code,
    page title, and web server fingerprint. Returns structured F1 signals:
    tech_stack_detected, server_version_disclosed, http_to_https_redirect.
    Always call this first — every other tool is meaningless if the target
    is down.
    """
    raw = TOOL_REGISTRY["httpx"]().run(target)
    parsed = parse_httpx(raw, target)
    signals_str = json.dumps(parsed["signal_candidates"], indent=2)
    return f"Signals:\n{signals_str}\n\nSummary: {parsed['semantic_summary']}"


@tool
def run_whatweb(target: str) -> str:
    """
    Run whatweb to fingerprint web technologies on the target: CMS
    (WordPress, Drupal, Joomla), frameworks (PHP, ASP.NET), JavaScript
    libraries (jQuery, React), and web servers (nginx, Apache, IIS).
    Use when the prompt asks about tech stack or what software the target runs.
    """
    raw = TOOL_REGISTRY["whatweb"]().run(target)
    if not _ok(raw):
        return f"whatweb failed: {raw.get('raw', 'unknown error')}"

    if raw.get("mode") == "real":
        return f"whatweb raw output:\n{raw.get('raw', '')[:2000]}"

    tech = raw.get("tech_stack", [])
    if not tech:
        return "whatweb found no identifiable technologies."
    return f"Technologies detected: {', '.join(str(t) for t in tech)}"


@tool
def run_wafw00f(target: str) -> str:
    """
    Run wafw00f to detect whether a Web Application Firewall (WAF) is
    protecting the target, and which vendor (Cloudflare, Akamai, AWS WAF,
    ModSecurity, F5, etc.). WAF presence affects which attack techniques
    are viable in later pipeline phases.
    Use when the prompt mentions WAF, firewall, or protection layer.
    """
    raw = TOOL_REGISTRY["wafw00f"]().run(target)
    if not _ok(raw):
        return f"wafw00f failed: {raw.get('raw', 'unknown error')}"

    if raw.get("mode") == "real":
        return f"wafw00f raw output:\n{raw.get('raw', '')[:2000]}"

    detected = raw.get("waf_detected", False)
    waf_name = raw.get("waf_name", "none")
    confidence = raw.get("confidence", "n/a")
    if detected:
        return f"WAF detected: {waf_name} (confidence: {confidence})"
    return "No WAF detected."


@tool
def run_shcheck(target: str) -> str:
    """
    Run shcheck to audit HTTP security response headers. Checks for presence
    or absence of: Content-Security-Policy, Strict-Transport-Security,
    X-Frame-Options, X-Content-Type-Options, Permissions-Policy.
    Missing headers are a misconfiguration finding (signal: missing_security_headers).
    Use when the prompt mentions headers, header posture, or security configuration.
    """
    raw = TOOL_REGISTRY["shcheck"]().run(target)
    if raw.get("mode") == "mock":
        missing = raw.get("missing_headers", [])
        present = raw.get("present_headers", [])
        parts = []
        if missing:
            parts.append(f"Missing security headers: {', '.join(missing)}")
        if present:
            parts.append(f"Present headers: {', '.join(present)}")
        return "\n".join(parts) if parts else "shcheck returned no header data."
    # real mode
    if not _ok(raw):
        return f"shcheck failed: {raw.get('raw', 'unknown error')}"
    return f"shcheck raw output:\n{raw.get('raw', '')[:2000]}"


@tool
def run_testssl(target: str) -> str:
    """
    Run testssl to assess TLS/SSL configuration: supported protocol versions
    (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3), weak or deprecated ciphers,
    certificate validity and days until expiry, and known TLS vulnerabilities
    (BEAST, POODLE, CRIME, ROBOT, Heartbleed).
    Use when the prompt mentions TLS, SSL, certificate, HTTPS, or cipher.
    """
    raw = TOOL_REGISTRY["testssl"]().run(target)
    if not _ok(raw):
        return f"testssl failed: {raw.get('raw', 'unknown error')}"

    if raw.get("mode") == "real":
        return f"testssl raw output:\n{raw.get('raw', '')[:3000]}"

    tls_vers = raw.get("tls_versions", [])
    weak = raw.get("weak_protocols_found", "unknown")
    expiry = raw.get("cert_expiry_days", "unknown")
    return (
        f"TLS versions supported: {', '.join(tls_vers) if tls_vers else 'unknown'}\n"
        f"Weak/deprecated protocols found: {weak}\n"
        f"Certificate expiry (days remaining): {expiry}"
    )


@tool
def run_nmap(target: str) -> str:
    """
    Run nmap to enumerate open TCP ports on the target host. Identifies
    exposed services beyond the standard web ports (80/443): SSH (22),
    FTP (21), Telnet (23), RDP (3389), database ports (3306, 5432, 27017),
    and admin panels on non-standard ports.
    Use when the prompt mentions ports, exposed services, or network surface.
    """
    raw = TOOL_REGISTRY["nmap"]().run(target)
    if not _ok(raw):
        return f"nmap failed: {raw.get('raw', 'unknown error')}"

    if raw.get("mode") == "real":
        return f"nmap raw output:\n{raw.get('raw', '')[:2000]}"

    ports = raw.get("open_ports", [])
    if not ports:
        return "nmap found no open ports in the top-100 scan."
    lines = [f"  port {p['port']}/{p.get('service', 'unknown')}" for p in ports]
    return "Open ports:\n" + "\n".join(lines)


@tool
def run_wpscan(target: str) -> str:
    """
    Run wpscan to enumerate WordPress-specific details: WordPress version,
    installed plugins (including outdated or vulnerable ones), active themes,
    user enumeration, and known CVEs for detected components.
    ONLY call this if the target is confirmed to be running WordPress —
    either from run_whatweb output, or if the prompt explicitly asks about
    WordPress or plugin vulnerabilities.
    """
    raw = TOOL_REGISTRY["wpscan"]().run(target)
    if not _ok(raw):
        return f"wpscan failed: {raw.get('raw', 'unknown error')}"

    if raw.get("mode") == "real":
        return f"wpscan raw output:\n{raw.get('raw', '')[:3000]}"

    is_wp = raw.get("is_wordpress", False)
    if not is_wp:
        return "wpscan: target does not appear to be running WordPress."

    version = raw.get("wp_version", "unknown")
    vuln_plugins = raw.get("vulnerable_plugins", [])
    parts = [f"WordPress version: {version}"]
    if vuln_plugins:
        parts.append(f"Vulnerable plugins: {', '.join(str(p) for p in vuln_plugins)}")
    else:
        parts.append("No vulnerable plugins detected.")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Tool list passed to LangGraph
# ---------------------------------------------------------------------------

TOOLS = [
    run_httpx,
    run_whatweb,
    run_wafw00f,
    run_shcheck,
    run_testssl,
    run_nmap,
    run_wpscan,
]


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are Scout, a specialist web application security reconnaissance agent
responsible for Phase 1 (F1 Fingerprinting) of the Obsidia recon pipeline.

Your job: fingerprint the target. Confirm it is alive, identify its tech stack,
detect any WAF, assess TLS posture, check security headers, and note open ports.
You are NOT running exploit payloads or active vulnerability scans.

Your tools: run_httpx, run_whatweb, run_wafw00f, run_shcheck, run_testssl,
run_nmap, run_wpscan.

Rules:
1. Always call run_httpx first. Confirm the target is alive before using any
   other tool. If httpx reports the target is down, stop and report that.
2. Only call run_wpscan if WordPress is confirmed by run_whatweb output,
   or if the prompt explicitly asks about WordPress.
3. Do not call any tool more than once per target in a single task.
4. When you have gathered enough information to answer the prompt fully,
   write a clear final answer. Reference specific signals and values from
   tool output — not generic descriptions.
5. Your final answer must address: liveness, tech stack, WAF status, and
   any notable findings (header gaps, TLS issues, exposed non-web ports).
6. When you have run all required tools, stop calling tools and write your final answer immediately. Do not call any tool more than once.
"""


# ---------------------------------------------------------------------------
# Main entry point — called from main.py
# ---------------------------------------------------------------------------

def run_react_agent(prompt: str, target: str, context: dict) -> dict:
    """Run the Scout ReAct agent and return the contract-spec response JSON.

    Returns:
        {
            "agent_id": "agent-scout",
            "status":   "completed" | "failed",
            "response": {
                "summary":         str,   # LLM final answer
                "findings":        list,  # per-tool raw output blocks
                "reasoning_trace": list   # intermediate LLM steps for demo
            }
        }
    """
    agent = create_react_agent(_llm, TOOLS, prompt=SYSTEM_PROMPT)

    context_str = json.dumps(context) if context else "none"
    full_prompt = (
        f"Task: {prompt}\n"
        f"Target: {target}\n"
        f"Upstream context from prior agents: {context_str}\n"
        f"Always pass the exact target URL unchanged to every tool. Never modify, truncate, or retype the target string."
    )

    try:
        result = agent.invoke(
            {"messages": [("user", full_prompt)]},
            config={"recursion_limit": 25},  # 7 tools + LLM reasoning steps
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "agent_id": AGENT_ID,
            "status": "failed",
            "response": {"error": str(exc)},
        }

    messages = result.get("messages", [])
    final_content = messages[-1].content if messages else "No response generated."

    # reasoning_trace: all intermediate steps except the final answer
    reasoning_trace = []
    for msg in messages[:-1]:
        msg_type = type(msg).__name__
        content = getattr(msg, "content", "")
        if not content and hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                reasoning_trace.append({
                    "type": "action",
                    "tool": tc.get("name", "unknown"),
                    "args": tc.get("args", {}),
                })
        elif content:
            reasoning_trace.append({"type": msg_type, "content": content})

    # Build intent map: tool_call_id → LLM reasoning that prompted this call
    intent_map = {}
    for msg in messages:
        if type(msg).__name__ == "AIMessage" and hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                intent_map[tc.get("id", "")] = msg.content or f"run {tc.get('name', 'tool')}"

    # findings: one entry per ToolMessage (tool call result)
    findings = []
    for msg in messages:
        if type(msg).__name__ == "ToolMessage":
            output = msg.content
            intent = intent_map.get(getattr(msg, "tool_call_id", ""), "unknown")
            findings.append({
                "tool": getattr(msg, "name", "unknown"),
                "intent": intent,
                "output": output,
                "intent_satisfied": "yes" if "failed" not in output.lower() and "no output" not in output.lower() else "no",
            })

    # Forced-run safety net: run any tool the LLM skipped so findings are always complete
    called_tool_names = {f["tool"] for f in findings}
    tool_fn_map = {t.name: t for t in TOOLS}
    for tool_name, tool_fn in tool_fn_map.items():
        if tool_name not in called_tool_names:
            try:
                output = str(tool_fn.invoke({"target": target}))
            except Exception as exc:  # noqa: BLE001
                output = f"{tool_name} forced-run failed: {exc}"
            intent = f"forced run — LLM skipped {tool_name}"
            findings.append({
                "tool": tool_name,
                "intent": intent,
                "output": output,
                "intent_satisfied": "yes" if "failed" not in output.lower() and "no output" not in output.lower() else "no",
            })

    # Synthesis: ground the final summary in all tool findings via a second LLM call
    findings_text = "\n\n".join(
        f"[{f['tool']}]\n{f['output']}" for f in findings
    )
    synthesis_prompt = (
        f"You are Scout, a security reconnaissance agent. "
        f"Based on the tool findings below for target {target}, write a concise "
        f"fingerprinting summary covering: liveness, tech stack, WAF status, "
        f"TLS posture, security headers, and open ports.\n\n{findings_text}"
    )
    try:
        synthesis_result = _llm.invoke([("user", synthesis_prompt)])
        final_content = synthesis_result.content
    except Exception:  # noqa: BLE001
        pass  # keep final_content from messages[-1] as fallback

    return {
        "agent_id": AGENT_ID,
        "status": "completed",
        "response": {
            "summary": final_content,
            "findings": findings,
            "reasoning_trace": reasoning_trace,
        },
    }
