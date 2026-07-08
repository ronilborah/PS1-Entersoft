# Day 23 Walkthrough — Analyst→Prober Orchestrator Pipeline

## What Changed

We transitioned the Team 4 (Active Prober) pipeline from a two-agent internal chain into a **three-phase centralized orchestrator** that implements the Day 23 "sub-agent as tool" pattern across team boundaries.

### New Architecture

```
agent-analyst (Team 3, :8000)   →   Scout (internal)   →   Analyst (internal)
  secret / endpoint scanner           surface discovery        active vuln scan
        Phase 0                          Phase 1                   Phase 2
```

The **orchestrator** is `pipeline.py`. It owns the full DAG and state — calling each agent, holding results, and deciding what context to pass forward. No agent calls another directly.

### Files Modified / Added

| File | Change |
|---|---|
| [`agent_caller.py`](file:///Users/ronil/Documents/PS/Day-21/agent_caller.py) | **NEW** — HTTP client for upstream `agent-analyst`. Provides `call_upstream_analyst()` + `format_upstream_context()`. Falls back gracefully on connection errors. |
| [`agent_analyst.py`](file:///Users/ronil/Documents/PS/Day-21/agent_analyst.py) | Updated `run_analyst(target, context)` to accept a **natural-language summary string** instead of a structured `HandoffEnvelope` dict. Python-level early-exit if context signals failure/offline. |
| [`pipeline.py`](file:///Users/ronil/Documents/PS/Day-21/pipeline.py) | Added Phase 0 (upstream agent call), updated Phase 1 (Scout, passes upstream context into mock summary), updated Phase 2 (Analyst receives merged upstream + Scout context). Added `--upstream-url` and `--mock-upstream` CLI flags. |

---

## How the Handoff Works

### Phase 0 → Phase 1 (Analyst team → Scout)

`call_upstream_analyst(target)` POSTs to `http://localhost:8000/agents/agent-analyst/tasks`:

```json
{
  "prompt": "Perform secret scanning and endpoint discovery...",
  "target": "https://demo.testfire.net",
  "context": {}
}
```

Response (from `WannabeExpertCSDude1511/agent_analyst`):

```json
{
  "agent_id": "agent-analyst",
  "status": "completed",
  "response": {
    "summary": "Found 2 secrets... 3 live endpoints...",
    "findings": [
      { "type": "Secret", "tool": "trufflehog", "severity": "CRITICAL", ... },
      { "type": "Endpoint", "tool": "linkfinder", "location": "/api/v1/login", ... }
    ]
  }
}
```

`format_upstream_context()` compresses this into a plain-text block:

```
=== UPSTREAM CONTEXT (from agent-analyst) ===
agent-analyst completed secret + endpoint scan...
Secrets confirmed (2): AWS_ACCESS_KEY_ID... | hardcoded JWT secret...
Endpoints discovered (3): /api/v1/users, /api/v1/login, /admin/dashboard
=== END UPSTREAM CONTEXT ===
```

### Phase 1 → Phase 2 (Scout → Analyst)

In mock mode, the upstream context block is appended to Scout's `scout_summary` string. In real-LLM mode, the orchestrator explicitly merges:

```python
merged_context = upstream_context_str + "\n\n" + scout_summary
analyst_result = run_analyst(target, merged_context)
```

The Analyst agent (`agent_analyst.py`) receives this merged context string, reasons over both upstream signals (secrets, endpoints) and Scout signals (paths, tech stack) to decide which active-scan tools to run.

**Key effect:** When the upstream context mentions `login_endpoint` or `/api/`, the Analyst adds `run_kxss` and `run_corsy` to its tool selection — signals it would not have run from Scout alone.

---

## Verified Outputs

All four modes run with `--mock-llm --mock-upstream`:

### Happy Path

```bash
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream
```

- Phase 0: agent-analyst → 2 secrets, 3 endpoints
- Phase 1: Scout → 4 paths, 7 signals
- Phase 2: Analyst → ran `nuclei_active` + `testssl_deep` + `corsy` (corsy triggered by upstream `api_endpoint` signal)
- **pipeline_status: completed**

### Kill Mode

```bash
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --break-mode kill
```

- Phase 0: agent-analyst → OK (upstream is independent of Scout)
- Phase 1: Scout → **timeout** (envelope: `scout_status=timeout, target_live=False`)
- Phase 2: Analyst **halted immediately** — Python-level early exit before any LLM call
- **pipeline_status: scout_failed**

> **Observation:** Even when Scout fails, Phase 0 succeeded. An improvement would be to let the Analyst run on upstream findings alone when Scout times out — the upstream context already has live endpoints.

### Garbage Mode

```bash
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --break-mode garbage
```

- Phase 0: agent-analyst → OK (real target)
- Phase 1: Scout → ran against `http://[INVALID-HOST-99999]` — returned paths relative to the wrong host
- Phase 2: Analyst → ran and found signals, but `disc_paths` all point to the invalid host
- **pipeline_status: completed** (false success — ground truth mismatch)

> **Observation:** The pipeline emits `status=completed` even though all discovered paths are on the wrong host. This is the classic garbage-in/garbage-out failure mode. The proposed fix: add a `host_mismatch` check in the orchestrator comparing `upstream_result["target"]` against `envelope["target"]`.

### Delay Mode

```bash
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --break-mode delay
```

- Phase 0 + Phase 1: normal (~0s)
- Artificial 5s delay injected between Scout and Analyst
- Phase 2: normal
- **Total wall time: 5.01s** vs 0.00s for happy path

> **Observation:** With Phase 0 added, latency now stacks across 3 agents. Real LLM inference (15–30s/call) would yield: Phase 0 (30s) + Phase 1 (30s) + Phase 2 (30s) = ~90s. A Phase 0 timeout (no upstream watchdog) would block the entire pipeline indefinitely.

---

## Running the Pipeline

```bash
# Happy path (mock everything — works offline)
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream

# With real upstream agent running at localhost:8000
python pipeline.py --target https://demo.testfire.net --mock-llm

# With custom upstream URL
python pipeline.py --target https://demo.testfire.net --mock-llm --upstream-url http://192.168.1.42:8000

# All break modes
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --break-mode kill
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --break-mode garbage
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --break-mode delay

# Save output to JSON
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream -o pipeline_happy.json
```
