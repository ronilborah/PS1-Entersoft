"""
selector.py — Person B owns this file.

Decides which tools to run based on the natural-language prompt.

Uses Ollama (local LLM) to interpret the prompt and return a list
of tool names. If Ollama is not running or times out, falls back
to simple keyword rules so the agent always works.

ALLOWED tools for agent-analyst (the allowlist):
    trufflehog, secretfinder, linkfinder, gitleaks, git_secrets,
    mapextractor, jshole, nuclei_passive, httpx_enrichment, httpx
"""

import json
import logging
import os
from openai import OpenAI

logger = logging.getLogger("agent-analyst.selector")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL","https://ollama.com/v1",)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "gpt-oss:120b")
client = OpenAI(base_url=OLLAMA_BASE_URL,api_key=os.getenv("OLLAMA_API_KEY"),)

ALLOWED_TOOLS = [
    "trufflehog",
    "secretfinder",
    "linkfinder",
    "gitleaks",
    "git_secrets",
    "mapextractor",
    "jshole",
    "nuclei_passive",
    "httpx_enrichment",
    "httpx",
]

# Used by Ollama so it knows what tools exist
TOOL_DESCRIPTIONS = """
trufflehog      - scans files for leaked secrets (AWS keys, GitHub tokens, API keys)
secretfinder    - scans JavaScript files for API keys, tokens, passwords
linkfinder      - extracts hidden API endpoints and routes from JavaScript files
gitleaks        - detects secrets inside git repositories using pattern matching
git_secrets     - checks source code for accidentally committed credentials
mapextractor    - extracts exposed JavaScript source maps (.js.map files)
jshole          - detects known vulnerable JavaScript libraries (e.g. old jQuery)
nuclei_passive  - runs passive Nuclei templates (exposed panels, config issues)
httpx_enrichment - collects HTTP metadata like headers, status codes, redirects
httpx           - verifies the target is alive and reachable
"""


def _ask_ollama(prompt: str) -> list[str] | None:
    """
    Ask the local Ollama model which tools to run.
    Returns a list of tool names, or None if Ollama is unavailable.
    """
    system_message = """You are a security tool selector.

Return ONLY a JSON array.

Allowed tools:
[
"trufflehog",
"secretfinder",
"linkfinder",
"gitleaks",
"git_secrets",
"mapextractor",
"jshole",
"nuclei_passive",
"httpx_enrichment",
"httpx"
]

Always include "httpx".

Do not explain your reasoning.
Do not output markdown.
"""

    user_message = prompt

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": user_message,
        "system": system_message,
        "stream": False,
    }).encode("utf-8")

    try:
        response = client.chat.completions.create(
            model=OLLAMA_MODEL,temperature=0,
            messages=[{"role": "system",
                       "content": system_message,
                       },
                       {
                           "role": "user",
                           "content": user_message,
                           },
                           ],
                           )
        raw = response.choices[0].message.content.strip()
        raw = raw.replace("```json", "").replace("```", "").strip()
        tool_list = json.loads(raw)
        valid = [t for t in tool_list if t in ALLOWED_TOOLS]
        if valid:
            logger.info("Ollama selected tools: %s", valid)
            return valid

    except Exception as e:
        logger.warning(
            "Ollama unavailable (%s). Using keyword fallback.",
            e,
        )
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("Could not parse Ollama response: %s — using keyword fallback", e)

    return None


def _keyword_fallback(prompt: str) -> list[str]:
    """
    Simple keyword-based tool selection used when Ollama is unavailable.
    No AI needed — just check what words are in the prompt.
    """
    prompt_lower = prompt.lower()
    selected = set()

    if any(w in prompt_lower for w in ["secret", "credential", "token", "key", "password", "leak"]):
        selected.update(["trufflehog", "gitleaks", "secretfinder", "git_secrets"])

    if any(w in prompt_lower for w in ["javascript", "js", "script", "bundle"]):
        selected.update(["linkfinder", "secretfinder", "jshole"])

    if any(w in prompt_lower for w in ["endpoint", "api", "route", "path", "url"]):
        selected.update(["linkfinder", "mapextractor"])

    if any(w in prompt_lower for w in ["sourcemap", "source map", ".map"]):
        selected.update(["mapextractor"])

    if any(w in prompt_lower for w in ["passive", "header", "misconfig", "panel", "exposed"]):
        selected.update(["nuclei_passive", "httpx_enrichment"])

    if any(w in prompt_lower for w in ["library", "vulnerable", "outdated", "cve"]):
        selected.update(["jshole"])

    if not selected:
        logger.info("Keyword fallback found no matching tools.")
        return []

    # Always include httpx for liveness check
    selected.add("httpx")

    result = list(selected)
    logger.info("Keyword fallback selected tools: %s", result)
    return result


def select_next_tool(
    prompt: str,
    findings: list[dict],
    used_tools: list[str],
    planner_feedback: list[str],
) -> dict:
    """
    Decide the next tool to execute.

    Returns:
    {
        "finish": bool,
        "tool": "<tool name>"
    }
    """

    system_message = f"""
You are a passive security analysis planner.

Available tools:

{TOOL_DESCRIPTIONS}

Only respond to requests related to passive security analysis.

First, determine whether the user's request is related to passive security analysis.

If it is NOT related, immediately return:

{{
    "unsupported": true
}}

Do not evaluate tool selection or whether the analysis is complete for unrelated requests.

Only if the request IS related to passive security analysis should you decide whether to execute another tool or finish.

Select exactly one tool at a time.

Never select a tool that has already been executed.

Base each decision on the user's request, the findings collected so far, the tools already executed, and any planner feedback.

Prefer selecting another allowed tool whenever there is a reasonable possibility that it will produce additional meaningful passive security information.

Do not finish simply because some findings have already been collected.
Do not finish if there are zero used tools.


Only return "finish": true when you are confident that no remaining allowed tool is likely to provide any relevant or meaningful additional passive security findings. If there is even a slight chance they may provide meaningful additional information, do not finish.

If another tool should be executed, return:

{{
    "finish": false,
    "tool": "<tool name>"
}}

Otherwise, return:

{{
    "finish": true
}}
Never return empty. Return ONLY valid JSON
"""

    user_message = f"""
User request:
{prompt}

Already executed:
{used_tools}

Planner feedback:
{planner_feedback}

Current findings:
{json.dumps(findings, indent=2)}

Based on the user's request, the findings collected so far, the tools already executed, and any planner feedback, determine the single best next action.

If the user's request is not related to passive security analysis, return {{"unsupported": true}} immediately.

Prefer executing another allowed tool whenever it could reasonably produce additional meaningful passive security information.

Do not finish merely because previous tools produced findings.
Do not finish if there are 0 used tools.
Do not finish if there is even a slight chance that another allowed tool could reasonably produce additional meaningful passive security information.

If another tool should be executed, return:

{{"finish": false, "tool": "<tool name>"}}

Only if you are confident that no remaining allowed tool is likely to produce meaningful additional passive security findings, return:

{{"finish": true}}
"""

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": user_message,
        "system": system_message,
        "stream": False,
    }).encode("utf-8")

    try:
        response = client.chat.completions.create(
            model=OLLAMA_MODEL,
            temperature=0,
            timeout=150,
            messages=[
                {
                    "role": "system",
                    "content": system_message,
                },
                {
                    "role": "user",
                    "content": user_message,
                },
            ],
        )

        raw = response.choices[0].message.content.strip()

        raw = raw.replace("```json", "").replace("```", "").strip()

        if not raw:
            raise ValueError("Empty response from LLM")
        logger.info("Raw planner response:\n%s", raw)    
        decision = json.loads(raw)
        if decision.get("unsupported"):
            return {
                "unsupported": True,
                }
        logger.info("Cloud LLM decision: %s", decision)

        if decision.get("finish"):
            # HARD GUARD: the system prompt already instructs the model
            # not to finish with 0 tools used, but LLMs don't reliably
            # follow every instruction every time — this enforces it in
            # code so a single flaky planner response can never zero out
            # an entire scan. If the model tries to finish before running
            # anything, we override it and force a real tool to run
            # first via the same keyword fallback used when the LLM is
            # unavailable.
            if not used_tools:
                logger.warning(
                    "Planner returned finish=true with 0 tools used — "
                    "overriding and forcing at least one tool to run first."
                )
                fallback = [t for t in _keyword_fallback(prompt) if t not in used_tools]
                if fallback:
                    return {"finish": False, "tool": fallback[0]}
                # keyword fallback also found nothing — httpx is always
                # safe/cheap to run and gives at least a liveness check
                return {"finish": False, "tool": "httpx"}
            return {"finish": True}

        tool = decision.get("tool")
            
        if tool in used_tools:
                return {
                    "finish": False,
                    "tool": None,
                    "feedback": f"'{tool}' has already been executed. Choose a different tool",
                    }
            

        if not tool or tool not in ALLOWED_TOOLS:
                return {
                    "finish": False,
                    "tool": None,
                    "feedback": f"'{tool}' is not an allowed tool. Choose only from: {', '.join(ALLOWED_TOOLS)}",
                    }

        return {
                "finish": False,
                "tool": tool,
            }

    except Exception as e:
        logger.warning("Planner failed: %s", e)

    remaining = [t for t in _keyword_fallback(prompt) if t not in used_tools]

    if remaining:
        return {
            "finish": False,
            "tool": remaining[0],
        }

    return {"finish": True}
