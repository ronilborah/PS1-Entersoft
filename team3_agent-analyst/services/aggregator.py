"""
aggregator.py — Person B owns this file.

Takes the flat list of findings from runner.py and builds the
final structured response that the API returns.

Because every tool normalizes to the same schema, this file
never needs to know which tool produced which finding.
That's the whole point of normalization.
"""
import logging

from services.summarizer import summarize_findings

logger = logging.getLogger("agent-analyst.aggregator")


def aggregate(findings: list[dict], context_data: dict) -> dict:
    """
    Build the final response dict from a flat list of findings.

    Returns:
    {
        "summary":  "human-readable one-liner",
        "findings": [ ...normalized finding dicts... ]
    }
    """
    """
    //old method
    secrets       = [f for f in findings if f.get("type") == "Secret"]
    endpoints     = [f for f in findings if f.get("type") == "Endpoint"]
    vulns         = [f for f in findings if f.get("type") == "Vulnerability"]
    info_findings = [f for f in findings if f.get("type") == "Info"]

    # Build a readable summary sentence
    parts = []
    if secrets:
        parts.append(f"{len(secrets)} potential secret(s) detected")
    if endpoints:
        parts.append(f"{len(endpoints)} hidden endpoint(s) discovered")
    if vulns:
        parts.append(f"{len(vulns)} passive vulnerability indicator(s) found")
    if info_findings and not (secrets or endpoints or vulns):
        parts.append(f"{len(info_findings)} informational item(s) collected")
    if not parts:
        parts.append("no issues found during passive analysis")
    """

    summary = summarize_findings(findings, context_data)
    logger.info("Analyst Summary:\n%s", summary)

    return {
        "summary":  summary,
        "findings": findings,
    }
    

