"""LangGraph ReAct orchestrator for the Obsidia specialist-agent pipeline."""

import json
import os
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools import (
    PIPELINE_AGENTS,
    TOOLS,
    TOOL_TO_AGENT,
    reset_original_target,
    set_original_target,
)

load_dotenv()

_llm = ChatOpenAI(
    model=os.getenv("OLLAMA_MODEL", "gpt-oss:20b"),
    base_url=os.getenv("OLLAMA_BASE_URL", "https://ollama.com/v1"),
    api_key=os.getenv("OLLAMA_API_KEY"),
    temperature=0,
)

SYSTEM_PROMPT = """You are the Obsidia recon-pipeline orchestrator. You coordinate five specialist
agents in this order: Scout → Mapper → Analyst → Prober → Striker. Call agents in
logical order based on what each returns. For every downstream call after the first,
you MUST pass the previous agent's complete JSON output in that tool call's `context`
argument, accumulating useful findings from earlier stages. If an agent returns JSON
with `skipped: true`, record that it was unavailable and continue; do not abort.

Pipeline order is STRICT and must not be skipped: Scout → Mapper → Analyst → Prober →
Striker. You MUST call call_prober before call_striker, no exceptions. Prober validates
and confirms findings from Analyst with active (safe) tests. Striker only runs after
Prober has returned its results. If Prober returns empty findings or an error, still
call call_striker with whatever context is available — do not skip it. The only valid
reason to skip an agent is if it returns skipped:true due to being unreachable.

Striker invocation rule: Call call_striker after call_prober has completed, if ANY of
the following are true: (1) Analyst found secrets, credentials, or API keys in
client-side code; (2) Prober confirmed at least one finding of any severity; (3) Analyst
flagged exposed configuration files, injection points, or open redirects. Striker
operates in mock mode and will not cause real damage — it is safe to invoke.

Run every relevant pipeline stage, but never call a specialist agent more than once in
a run. Once all relevant stages are complete, write a concise executive summary from
all available findings. Do not reveal your chain of thought or internal tool trace.

Never call more than one tool in a single step. Always wait for each tool result before deciding on the next action.
"""


def _structured_result(value: Any) -> dict[str, Any]:
    """Normalize nested or encoded tool output into the public result shape."""
    for _ in range(3):
        if not isinstance(value, str):
            break
        stripped = value.strip()
        if stripped.startswith(("{", "[", '"')):
            try:
                decoded = json.loads(stripped)
                if decoded == value:
                    break
                value = decoded
            except json.JSONDecodeError:
                break
        else:
            break

    if not isinstance(value, dict):
        return {"summary": str(value), "findings": []}

    summary = value.get("summary", "")
    if isinstance(summary, str):
        stripped = summary.strip()
        if stripped.startswith("{"):
            try:
                inner = json.loads(stripped)
                if isinstance(inner, dict):
                    value = inner
            except json.JSONDecodeError:
                pass

    findings = value.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    return {
        "summary": str(value.get("summary", value.get("error", "No summary returned."))),
        "findings": findings,
    }


async def run_orchestrator(prompt: str, target: str) -> dict:
    """Run the ReAct graph and return a summary plus sanitized pipeline results."""
    graph = create_react_agent(
        _llm,
        tools=TOOLS,
        prompt=SYSTEM_PROMPT,
    )
    target_token = set_original_target(target)
    try:
        result = await graph.ainvoke(
            {"messages": [HumanMessage(content=f"Target: {target}\nObjective: {prompt}")]},
            config={"recursion_limit": 30},
        )
    finally:
        reset_original_target(target_token)

    pipeline_results: dict[str, dict[str, Any]] = {}
    for message in result.get("messages", []):
        name = getattr(message, "name", None)
        if name in TOOL_TO_AGENT:
            pipeline_results[TOOL_TO_AGENT[name]] = _structured_result(getattr(message, "content", ""))

    for agent in PIPELINE_AGENTS:
        pipeline_results.setdefault(agent, {"summary": "Not invoked for this run.", "findings": []})

    final_content = "Orchestration completed; see pipeline results for available findings."
    for message in reversed(result.get("messages", [])):
        if getattr(message, "type", "") == "ai" and getattr(message, "content", None):
            final_content = str(message.content)
            break

    return {"summary": final_content, "pipeline_results": pipeline_results}
