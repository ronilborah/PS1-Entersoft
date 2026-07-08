# Day 23 Write-up: Multi-Agent Pipeline & Orchestration

**Target:** `https://demo.testfire.net`  
**Orchestrator:** `pipeline.py` (with `--break-mode kill|garbage|delay`)  
**Pipeline Topology:**  
`agent-analyst` (Team 3, port 8000) $\rightarrow$ `agent-prober` Orchestrator (`pipeline.py`) $\rightarrow$ `agent-striker` (Team 5, port 8005)

---

## 1. Multi-Agent Pipeline Topology & Handoff Contract

In the 5-agent coordinated security pipeline, Team 4 (`agent-prober`) occupies the critical active scanning step. The chain is wired together using the "sub-agent as tool" pattern orchestrated centrally by `pipeline.py`:

```
agent-analyst (Team 3, port 8000) [Secrets/Endpoints]
             ↓ (Phase 0: Upstream Context Summary)
agent-prober Orchestrator (pipeline.py)
   ├─→ Scout Agent (Phase 1: Surface Discovery)
   └─→ Analyst Agent (Phase 2: Active Vulnerability Scan)
             ↓ (Phase 3: Downstream Context Summary)
agent-striker (Team 5, port 8005) [Exploitation/PoC]
```

### Upstream Handoff (Team 3 $\rightarrow$ Team 4)
The orchestrator calls the upstream `agent-analyst` via HTTP `POST /agents/agent-analyst/tasks`. The returned response is parsed and compressed into a plain-text context block using `format_upstream_context()`. This provides Team 4 with:
- **Secrets confirmed** (e.g. leaked API keys, tokens) to help flag interesting configuration files.
- **API endpoints and login routes** to focus parameters fuzzing.

### Internal Handoff (Scout $\rightarrow$ Analyst)
The internal handoff is transitioned from the structured JSON `HandoffEnvelope` into a **natural-language summary context**. The Scout agent compresses its findings into a narrative string (e.g. live status, tech stack, discovered paths, and Nikto misconfigurations). 

The orchestrator combines the upstream context and the Scout summary into a single input context prompt for the Prober's Analyst agent. This allows the Analyst's ReAct loop to reason dynamically over both upstream findings and local surface discovery to select the best vulnerability scanners (e.g. `run_corsy` or `run_kxss` when endpoints are found).

### Downstream Handoff (Team 4 $\rightarrow$ Team 5)
The orchestrator compiles our confirmed vulnerability findings (tool inputs, outputs, severity, location) and hands them downstream to `agent-striker` via `POST /agents/agent-striker/tasks`. This allows the Striker agent to run targeted PoC scripts against verified vulnerabilities.

---

## 2. Observed Pipeline Output (Happy Path)

Executing the full 4-phase mock pipeline (`--mock-llm --mock-upstream --mock-striker`) produces the following logs:

```
──────────────────────────── PIPELINE START ────────────────────────────
  target        : https://demo.testfire.net
  break_mode    : None (happy path)
  llm mode      : mock (deterministic rules)
  upstream agent: mock response
  striker agent : mock response

─────────────────── PHASE 0 — Upstream agent-analyst ───────────────────
  agent-analyst : ok  (0.00s)  [mock]
  secrets found : 2
  endpoints     : /api/v1/users, /api/v1/login, /admin/dashboard
  summary       : agent-analyst completed secret + endpoint scan...

──────────────────────── PHASE 1 — Scout Agent ─────────────────────────
  [mock-llm] Scout running tools directly (no LLM)
    → run_httpx
    → run_ffuf
    → run_nikto
  Scout completed in 0.00s

─────────────────────── PHASE 2 — Analyst Agent ────────────────────────
  [mock-llm] Analyst reading HandoffEnvelope, picking tools by rule
    → run_nuclei_active  [Confirm active misconfigurations and CVEs]
    → run_testssl_deep   [Check for weak TLS protocol versions]
    → run_corsy          [Confirm CORS misconfiguration reflection]

────────────────── PHASE 3 — Downstream agent-striker ──────────────────
  agent-striker : ok  (0.00s)  [mock]
  confirmed PoCs: 2
  risk rating   : CRITICAL
  summary       : agent-striker completed PoC verification...

─────────────────────────── PIPELINE RESULT ────────────────────────────
  Upstream: ok  (0.00s)
  Scout   : completed  (0.00s)
  Analyst : completed  (0.00s)
  Striker : completed  (0.00s)
  Total   : 0.00s
  Tools used by Analyst : ['run_nuclei_active', 'run_testssl_deep', 'run_corsy']
  Analyst signals found : exposed_git, missing_csp_header, missing_hsts_header, weak_tls_version_or_ciphers
```

**Key Observation:** The Analyst agent dynamically executed `run_corsy` because the upstream context reported `/api/v1/users` as a live API endpoint, raising the `cors_misconfiguration` signal candidate.

---

## 3. Three Coordination Failures & Break-Mode Analysis

### Failure 1: Cascading Failure & Early Termination Handling (kill mode)
- **Injection:** Scout is simulated to time out, producing an empty timeout envelope with `scout_status="timeout"` and `target_live=False`.
- **Observed Behavior:** The orchestrator intercepts the Scout failure. The Analyst agent uses Python-level early-exit state guarding to immediately halt execution, returning an informative skip summary. The downstream Striker phase is called with the blocked context, preventing any exploit tool calls.
- **Orchestrator Status:** `scout_failed`.

### Failure 2: Silent Ground-Truth Host Mismatch (garbage mode)
- **Injection:** Scout is fed an invalid host target: `http://[INVALID-HOST-99999]`.
- **Observed Behavior:** Scout runs its mock tools against the invalid host, returning paths like `http://[INVALID-HOST-99999]/backup.zip`. The orchestrator patches the target back to `https://demo.testfire.net` before passing to Analyst, but the paths remain bound to the invalid host. Both agents report `completed` with zero HTTP/CLI errors, but all active scans are run against the wrong host.
- **Orchestrator Status:** `completed` (false success).

### Failure 3: Latency Stacking & Pipeline Blocking (delay mode)
- **Injection:** A 5.0-second delay is introduced after Scout completes but before Analyst starts.
- **Observed Behavior:** Total pipeline execution time jumps to 5.01s. In a real-world pipeline using 4 sequential LLM agents (each taking 15–30s for reasoning), latency stacks additively to ~60–120s. If any agent hangs without a watchdog timeout in the orchestrator, the entire deployment blocks indefinitely.

---

## 4. Orchestrator-Level Verification Outputs

The full execution outputs for all break modes are recorded in the following workspace JSON files:
1. [`pipeline_happy.json`](file:///Users/ronil/Documents/PS/Day-21/pipeline_happy.json) — End-to-end happy path execution with mock upstream/downstream context.
2. [`pipeline_kill.json`](file:///Users/ronil/Documents/PS/Day-21/pipeline_kill.json) — Scout timeout handles early termination without cascading failures.
3. [`pipeline_garbage.json`](file:///Users/ronil/Documents/PS/Day-21/pipeline_garbage.json) — Ground-truth mismatch where paths point to the invalid host.
4. [`pipeline_delay.json`](file:///Users/ronil/Documents/PS/Day-21/pipeline_delay.json) — Timeline timing stack verifying the 5.0-second orchestrator delay.
