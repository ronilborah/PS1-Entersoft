"""
selector.py
-----------
** KEPT FOR REFERENCE ONLY — no longer called by main.py **

The ReAct agent in agent.py has replaced this module.  The LLM now decides
which tools to run based on the prompt and what it observes from tool output,
rather than a fixed keyword map.

Original purpose:
Simple rule-based (keyword) tool selection for the Scout agent.

No LLM calls. Takes the natural-language prompt, lowercases it, and matches
keywords to the F1 fingerprinting tools they imply. This keeps the agent
deterministic and easy to explain in a demo: every tool chosen can be traced
back to a specific word or phrase in the prompt.

httpx is always included, because it is the shared liveness-check tool
across every team and Scout's whole job starts with "is it even up".
"""

# keyword -> tool name. Order doesn't matter; selection is keyword-driven, not priority-driven.
KEYWORD_MAP = {
    "live": "httpx",
    "up": "httpx",
    "reachable": "httpx",
    "tech": "whatweb",
    "stack": "whatweb",
    "technology": "whatweb",
    "cms": "whatweb",
    "waf": "wafw00f",
    "firewall": "wafw00f",
    "tls": "testssl",
    "ssl": "testssl",
    "certificate": "testssl",
    "cert": "testssl",
    "header": "shcheck",
    "headers": "shcheck",
    "security header": "shcheck",
    "port": "nmap",
    "ports": "nmap",
    "open port": "nmap",
    "wordpress": "wpscan",
    "wp": "wpscan",
    "plugin": "wpscan",
}

SCOUT_ALLOWLIST = {"httpx", "wafw00f", "whatweb", "shcheck", "testssl", "nmap", "wpscan"}


def select_tools(prompt: str) -> list[str]:
    """Return an ordered, deduplicated list of tool names implied by the prompt.

    Falls back to a sane default fingerprint sweep (httpx, whatweb, wafw00f)
    if no keyword in the prompt matches anything -- Scout should never run
    zero tools on a valid request.
    """
    prompt_lower = prompt.lower()
    selected: list[str] = []

    for keyword, tool in KEYWORD_MAP.items():
        if keyword in prompt_lower and tool not in selected:
            selected.append(tool)

    if "httpx" not in selected:
        selected.insert(0, "httpx")

    if len(selected) == 1:  # only httpx matched, prompt was vague
        for fallback in ("whatweb", "wafw00f"):
            if fallback not in selected:
                selected.append(fallback)

    # enforce allowlist defensively, even though every tool above is already in it
    selected = [t for t in selected if t in SCOUT_ALLOWLIST]
    return selected
