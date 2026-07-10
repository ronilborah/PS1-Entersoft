"""
summarizer.py

Uses the project's existing Ollama endpoint to convert the Analyst's
raw findings into a concise handoff for the next agent (Prober).

The summary is meant for another LLM, not for an end user.
"""

import json
import logging
import os
from openai import OpenAI

logger = logging.getLogger("agent-analyst.summarizer")

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "https://ollama.com/v1",
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "deepseek-v4-flash",
)

client = OpenAI(
    base_url=OLLAMA_BASE_URL,
    api_key=os.getenv("OLLAMA_API_KEY"),
)


def summarize_findings(findings: list[dict], context_data: dict) -> str:
    """
    Generate an LLM summary of the passive analysis results.

    Parameters
    ----------
    findings:
        Normalized findings from all passive tools.

    context_data:
        Parsed Mapper context (js_files, endpoints, urls).

    Returns
    -------
    str
        Concise summary for the next agent.
    """

    if not findings:
        return (
            "Passive analysis completed. No significant findings were detected. "
            "Continue probing any endpoints and assets discovered by Mapper."
        )

    system_message = """
You are the Analyst agent in a multi-agent penetration testing workflow.

Your output will be consumed by the Prober agent.

Summarize the passive analysis.

Focus on:
- Important discoveries
- Attack surface that should be actively investigated
- Suspected weaknesses
- Recommended probing priorities

Do NOT list every finding.
Do NOT output JSON.
Keep the response under 250 words.
"""

    user_message = f"""
Mapper Context:

{json.dumps(context_data, indent=2)}

Passive Findings:

{json.dumps(findings, indent=2)}
"""

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "system": system_message,
        "prompt": user_message,
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

        summary = response.choices[0].message.content.strip()

        if summary:
            return summary

    except Exception as e:
        logger.warning("Ollama summarization unavailable: %s", e)

    except Exception as e:
        logger.warning("Failed to summarize findings: %s", e)

    # Fallback summary
    return (
        f"Passive analysis identified {len(findings)} finding(s). "
        "Review the findings and prioritize active verification."
    )
