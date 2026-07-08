"""
agent.py
--------
LangGraph ReAct agent for Scout (Team 1, F1 Fingerprinting).

Replaces selector.py + the manual tool loop from main.py v1.

The LLM (Ollama via OpenAI-compatible endpoint) reads the prompt, decides
which Scout tools are relevant, calls them, reads each tool's structured
signal output, and reasons about what to do next. It stops when it has
enough to write a final answer, or when it has run all relevant tools.

Entry point: run_react_agent(prompt, target, context, intent) → called by main.py.

Env vars (loaded from .env):
    TOOL_MOCK_MODE    — true|false (controls tool execution, not LLM)
    OLLAMA_BASE_URL   — Ollama endpoint, default http://localhost:11434/v1
    OLLAMA_MODEL      — model name, default qwen2.5
"""

import json
import os

import requests
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
    model=os.getenv("OLLAMA_MODEL", "qwen2.5"),
    base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
    api_key=os.getenv("OLLAMA_API_KEY", "ollama"),  # Ollama ignores this; the client requires it
    temperature=0,          # deterministic = better for security reasoning
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ok(result: dict) -> bool:
    """Return True if the tool ran without error, in either mode."""
    if result.get("mode") == "mock":
        return True
    return bool(result.get("ok"))


# ---------------------------------------------------------------------------
# @tool wrappers — one per Scout allowlist entry
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
        output = raw.get("raw", "")
        if not output.strip():
            return "whatweb returned no output — target may have blocked the request or timed out."
        return f"whatweb raw output:\n{output[:2000]}"
    tech = raw.get("tech_stack", [])
    if not tech:
        return "whatweb found no identifiable technologies."
    return f"Technologies detected: {', '.join(str(t) for t in tech)}"


@tool
def run_wafw00f(target: str) -> str:
    """
    Run wafw00f to detect whether a Web Application Firewall (WAF) is
    protecting the target, and if so, which vendor (Cloudflare, Akamai,
    AWS WAF, ModSecurity, etc.). WAF presence affects which attack
    techniques are viable in later phases.
    Use when the prompt mentions WAF, firewall, or protection.
    """
    raw = TOOL_REGISTRY["wafw00f"]().run(target)
    if not _ok(raw):
        return f"wafw00f failed: {raw.get('raw', 'unknown error')}"
    if raw.get("mode") == "real":
        output = raw.get("raw", "")
        if "No WAF detected" in output:
            return "WAF detected: False\nWAF name: none\nConfidence: n/a"
        for line in output.splitlines():
            if "is behind" in line or "identified" in line.lower():
                return f"WAF detected: True\nWAF name: {line.strip()}\nConfidence: firm"
        return f"WAF detected: unknown\nRaw output:\n{output[:2000]}"
    detected = raw.get("waf_detected", False)
    waf_name = raw.get("waf_name", "none")
    confidence = raw.get("confidence", "n/a")
    if detected:
        return f"WAF detected: True\nWAF name: {waf_name}\nConfidence: {confidence}"
    return "WAF detected: False\nWAF name: none\nConfidence: n/a"


@tool
def run_shcheck(target: str) -> str:
    """
    Audit HTTP security response headers. Checks for presence or absence of:
    Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
    Missing headers are a misconfiguration finding (signal: missing_security_headers).
    Use when the prompt mentions headers, header posture, or security configuration.
    """
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    try:
        resp = requests.get(target, timeout=10, verify=True, allow_redirects=True)
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(target, timeout=10, verify=False, allow_redirects=True)
        except Exception as exc:
            return f"shcheck failed: {exc}"
    except Exception as exc:
        return f"shcheck failed: {exc}"

    present = [h for h in security_headers if h in resp.headers]
    missing = [h for h in security_headers if h not in resp.headers]

    parts = [f"HTTP status: {resp.status_code}"]
    if present:
        parts.append(f"Present headers: {', '.join(present)}")
    if missing:
        parts.append(f"Missing security headers: {', '.join(missing)}")
    server_hdr = resp.headers.get("Server")
    if server_hdr:
        parts.append(f"Server header: {server_hdr}")
    return "\n".join(parts)


@tool
def run_testssl(target: str) -> str:
    """
    Run testssl to assess TLS/SSL configuration: supported protocol versions
    (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3), weak or deprecated ciphers,
    certificate validity and days until expiry, and known TLS vulnerabilities
    (BEAST, POODLE, CRIME, ROBOT, Heartbleed).
    Use when the prompt mentions TLS, SSL, certificate, HTTPS, or cipher.
    """
    if target.startswith("http://"):
        return "TLS test skipped: target uses HTTP, not HTTPS. No TLS posture to assess."
    raw = TOOL_REGISTRY["testssl"]().run(target)
    if not _ok(raw):
        err = raw.get("raw", "unknown error")
        if "timed out" in err:
            return "TLS scan inconclusive — target did not respond within timeout. Manual testssl run recommended."
        return f"testssl failed: {err}"
    if raw.get("mode") == "real":
        output = raw.get("raw", "")
        if not output.strip():
            return "testssl returned no output — binary may have exited silently."
        return f"testssl raw output:\n{output[:3000]}"
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
4. You will be given a list of REQUIRED tools for this scan's intent. You
   MUST call every required tool before writing your final answer, even if
   you believe you already have enough information — skipping a required
   tool is a failure. The only exceptions are: run_testssl on an HTTP-only
   (non-HTTPS) target, and run_wpscan when WordPress is not confirmed.
5. When you have called every required tool, write a clear final answer.
   Reference specific signals and values from tool output — not generic
   descriptions.
6. Your final answer must address: liveness, tech stack, WAF status,
   security headers, TLS posture, and any notable findings (exposed
   non-web ports, misconfigurations).
"""


# ---------------------------------------------------------------------------
# Required tools per intent (enforced in code, not just prompt)
# ---------------------------------------------------------------------------

REQUIRED_BY_INTENT = {
    "fingerprint": ["run_httpx", "run_whatweb", "run_wafw00f", "run_shcheck", "run_testssl", "run_nmap"],
    "deep":        ["run_httpx", "run_whatweb", "run_wafw00f", "run_shcheck", "run_testssl", "run_nmap"],
    "stealth":     ["run_httpx", "run_whatweb"],
    "wordpress":   ["run_httpx", "run_whatweb", "run_wpscan"],
}


# ---------------------------------------------------------------------------
# Main entry point — called from main.py
# ---------------------------------------------------------------------------

def run_react_agent(prompt: str, target: str, context: dict, intent: str = "fingerprint") -> dict:
    """Run the Scout ReAct agent and return the contract-spec response JSON.

    Returns:
        {
            "agent_id": "agent-scout",
            "status":   "completed" | "failed",
            "response": {
                "summary":         str,   # LLM synthesized final report
                "findings":        list,  # per-tool raw output blocks
                "reasoning_trace": list   # intermediate LLM steps for demo
            }
        }
    """
    intent_guidance = {
        "fingerprint": "REQUIRED tools for this scan: run_httpx, run_whatweb, run_wafw00f, run_shcheck, run_testssl (skip only if target is HTTP-only), run_nmap. Skip run_wpscan unless WordPress is confirmed.",
        "deep":        "REQUIRED tools for this scan: run_httpx, run_whatweb, run_wafw00f, run_shcheck, run_testssl (skip only if target is HTTP-only), run_nmap, and run_wpscan if WordPress is detected. You must call every one of these before your final answer.",
        "stealth":     "REQUIRED tools for this scan: run_httpx, run_whatweb only. Minimise requests. Do NOT run run_nmap, run_wafw00f, run_shcheck, run_testssl, or run_wpscan under any circumstances.",
        "wordpress":   "REQUIRED tools for this scan: run_httpx, run_whatweb, run_wpscan. Focus on WordPress version and plugin vulnerabilities.",
    }.get(intent, "REQUIRED tools for this scan: run_httpx, run_whatweb, run_wafw00f, run_shcheck, run_testssl (skip only if target is HTTP-only), run_nmap.")

    dynamic_prompt = SYSTEM_PROMPT + f"\n\nScan intent: {intent}\nTool guidance for this intent: {intent_guidance}"

    agent = create_react_agent(_llm, TOOLS, prompt=dynamic_prompt)

    context_str = json.dumps(context) if context else "none"
    full_prompt = (
        f"Task: {prompt}\n"
        f"Target: {target}\n"
        f"Upstream context from prior agents: {context_str}"
    )

    try:
        result = agent.invoke(
            {"messages": [("user", full_prompt)]},
            config={"recursion_limit": 25},
        )
    except Exception as exc:  # noqa: BLE001
        return {
            "agent_id": AGENT_ID,
            "status": "failed",
            "response": {"error": str(exc)},
        }

    messages = result.get("messages", [])

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

    # findings: one entry per ToolMessage
    findings = []
    for msg in messages:
        if type(msg).__name__ == "ToolMessage":
            findings.append({
                "tool": getattr(msg, "name", "unknown"),
                "output": msg.content,
            })

    # -----------------------------------------------------------------------
    # Safety net: force-run any required tool the LLM skipped.
    # Small local models frequently stop early — this guarantees completeness.
    # -----------------------------------------------------------------------
    required = REQUIRED_BY_INTENT.get(intent, REQUIRED_BY_INTENT["fingerprint"])
    called_tool_names = {f["tool"] for f in findings}
    tool_fn_map = {t.name: t for t in TOOLS}

    for tool_name in required:
        if tool_name in called_tool_names:
            continue
        # Legitimate skip conditions
        if tool_name == "run_testssl" and target.startswith("http://"):
            continue
        if tool_name == "run_wpscan":
            whatweb_out = next((f["output"] for f in findings if f["tool"] == "run_whatweb"), "")
            if "wordpress" not in whatweb_out.lower():
                continue
        fn = tool_fn_map.get(tool_name)
        if not fn:
            continue
        try:
            output = str(fn.invoke({"target": target}))
        except Exception as exc:  # noqa: BLE001
            output = f"{tool_name} forced-run failed: {exc}"
        findings.append({
            "tool": tool_name,
            "output": output,
        })
        reasoning_trace.append({
            "type": "action",
            "tool": tool_name,
            "args": {"target": target},
            "note": "forced — LLM skipped this required tool",
        })

    # -----------------------------------------------------------------------
    # Synthesis: ask the LLM to write a proper report from all findings.
    # This runs after the safety net so forced-tool results are included.
    # -----------------------------------------------------------------------
    findings_text = "\n\n".join(
        f"[{f['tool']}]\n{f['output']}" for f in findings
    )
    synthesis_prompt = (
        f"You are Scout, a security reconnaissance agent. "
        f"You have completed a '{intent}' scan of {target}. "
        f"Based on the tool findings below, write a concise recon report covering: "
        f"liveness, tech stack, WAF status, TLS posture, security headers, open ports, "
        f"and any notable risks or misconfigurations. "
        f"Be specific — reference actual values from the tool output, not generic descriptions.\n\n"
        f"{findings_text}"
    )
    try:
        synthesis_result = _llm.invoke([("user", synthesis_prompt)])
        final_summary = synthesis_result.content
    except Exception:  # noqa: BLE001
        # Fallback: use the LLM's mid-loop answer if synthesis fails
        final_summary = messages[-1].content if messages else "No response generated."

    return {
        "agent_id": AGENT_ID,
        "status": "completed",
        "response": {
            "summary": final_summary,
            "findings": findings,
            "reasoning_trace": reasoning_trace,
        },
    }
