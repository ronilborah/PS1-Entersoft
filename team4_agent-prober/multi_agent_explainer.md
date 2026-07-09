# Multi-Agent Pipeline: Orchestrator, Handoff, Downstream

> **Status: ✅ Pipeline verified — all 4 phases completed successfully**

---

## The Big Picture: The 5-Agent Chain

```
Team 3                  Team 4 (YOU)                   Team 5
agent-analyst  ──→  [agent-scout → agent-analyst]  ──→  agent-striker
  :8000                      :8004                          :8005

[UPSTREAM]             [ORCHESTRATOR]                  [DOWNSTREAM]
```

Your codebase sits in the **middle** of a 5-team chain. You have two neighbours:
- **Upstream** (Team 3's `agent-analyst`): found secrets and endpoints *before* you.
- **Downstream** (Team 5's `agent-striker`): will exploit confirmed vulns *after* you.

---

## The Orchestrator (`pipeline.py`)

The **orchestrator** is the brain that sequences everything. It is **not an agent** — it has no LLM and makes no decisions. It is purely a coordinator that:

1. Calls agents in order
2. Takes each agent's output
3. Packages it as *context* for the next agent

**Why this pattern?** Agents never call each other directly. The orchestrator is the only thing that knows about the full chain. This keeps each agent dumb and focused on its own job.

```python
# pipeline.py — the orchestrator's 4 phases
upstream_result = call_upstream_analyst(target)          # Phase 0
envelope        = run_scout_mock(target, upstream_ctx)   # Phase 1
analyst_result  = run_analyst_mock(envelope, upstream_ctx) # Phase 2
striker_result  = call_downstream_striker(target, ctx)   # Phase 3
```

---

## The Handoff (`HandoffEnvelope`)

The **HandoffEnvelope** is the *structured message* that crosses the Scout → Analyst boundary. It is the most important concept in the pipeline.

```python
# This dict is what Scout hands off to Analyst
envelope = {
    "target":            "https://demo.testfire.net",
    "target_live":       True,           # ← Gate: Analyst HALTS if False
    "status_code":       200,
    "tech_stack":        ["nginx"],
    "discovered_paths":  ["/admin", "/.git", "/backup.zip"],
    "signal_candidates": ["exposed_git", "exposed_admin_panel", ...],
    "scout_summary":     "...",          # LLM narrative for Analyst to read
    "scout_tools_used":  ["run_httpx", "run_ffuf", "run_nikto"],
    "scout_status":      "completed",   # ← Gate: "timeout"/"failed" → Analyst halts
    "scout_error":       None,
}
```

**Why a structured envelope and not just a string?**  
The Analyst's *tool selection logic* reads specific fields (`target_live`, `signal_candidates`, `tech_stack`) to decide *which tools to run*. If Scout found `exposed_git`, Analyst knows to run `nuclei_active`. If Scout found HTTPS, Analyst knows to run `testssl_deep`. A plain string couldn't drive this logic reliably.

**Cascading failure guard** — `agent_analyst_mock.py` line 299:
```python
if scout_status in ("failed", "timeout") or not target_live:
    # Analyst halts — cannot scan a dead or unknown target
    return {"summary": "Analyst blocked: ...", "findings": []}
```

---

## The Two Agents Inside You

### Scout (`agent_scout.py`) — Surface Discovery Only
- Tools: `run_httpx`, `run_ffuf`, `run_nikto`
- Job: Map the attack surface (is the target live? what paths exist? what tech?)
- Output: **HandoffEnvelope**
- Hard rule: **DO NOT attempt vulnerability analysis** — just discover

### Analyst (`agent_analyst.py`) — Active Vuln Scanning
- Tools: `run_nuclei_active`, `run_testssl_deep`, `run_corsy`, `run_kxss`
- Job: Read the envelope's signals and confirm actual vulnerabilities
- Input: HandoffEnvelope + upstream context (secrets/endpoints from Team 3)
- Output: Confirmed findings with signal labels → passed to Striker

---

## Upstream Context (Team 3 → You)

`agent_caller.py` → `call_upstream_analyst()` calls Team 3 before Scout runs.

```
Team 3 finds: leaked AWS key in /static/app.js, /api/v1/login endpoint
         ↓
orchestrator calls format_upstream_context() → plain text block
         ↓
injected into Scout's prompt AND Analyst's prompt
         ↓
Analyst now knows to check /api/v1/login for CORS + XSS
```

If Team 3 is unreachable: **pipeline continues gracefully** — returns `status="unreachable"`, Analyst proceeds with Scout findings only.

---

## Downstream Context (You → Team 5)

`agent_caller.py` → `build_striker_context()` packages your confirmed findings for Team 5.

```python
# What you send to Team 5's agent-striker
{
    "summary": "Active scan found weak TLS + exposed .git + CORS vuln",
    "findings": [
        {"type": "xss_candidate",  "url": ".../search.aspx?q=test", "param": "q"},
        {"type": "sqli_candidate", "url": ".../login.aspx",         "param": "uid"},
    ]
}
```

Team 5 uses these typed candidates to attempt **read-only PoC exploits** and produce a final risk rating.

---

## Pipeline Flow (Verified Output)

```
PHASE 0  →  Upstream agent-analyst     ✅  ok  (mock)   secrets: 2, endpoints: 3
PHASE 1  →  Scout Agent               ✅  completed     signals: 7 (exposed_git, backup_file…)
                 ↓ HandoffEnvelope ↓
PHASE 2  →  Analyst Agent             ✅  completed     tools: nuclei+testssl+corsy, signals: 4
PHASE 3  →  Downstream agent-striker  ✅  ok  (mock)   confirmed PoCs: 2, risk: CRITICAL
```

**Total runtime (mock mode): ~0.00s** — all tools run with canned mock data.

---

## Break Modes (Failure Testing)

| Mode | What Happens | Effect |
|------|-------------|--------|
| `--break-mode kill` | Scout is replaced with a timeout envelope | Analyst reads `scout_status="timeout"` → halts |
| `--break-mode garbage` | Scout gets `http://[INVALID-HOST-####]` | httpx fails, no findings → Analyst gets empty envelope |
| `--break-mode delay` | `time.sleep(5)` before Analyst | Analyst still runs; demonstrates latency stacking |

---

## Run Commands

```bash
# Happy path (mock everything — works fully offline)
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker

# Test Scout timeout
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker --break-mode kill

# Test garbage input
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker --break-mode garbage

# Test with real upstream (Team 3 must be running at :8000)
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-striker
```
