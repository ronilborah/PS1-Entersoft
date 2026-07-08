# Multi-Agent Orchestrator Integration: Day 23 Specification & Flow

This document details the architectural design, API integration contracts, and data-flow mechanics implemented for the **Team 4 (Active Prober)** multi-agent orchestration pipeline.

---

## 1. Coordinated Security Pipeline Topology

In the full 5-agent security automation DAG, Team 4 (`agent-prober`) coordinates active port scanning, fingerprinting, and targeted vulnerability scanning. It acts as the bridge between static discovery (upstream) and verification/exploitation (downstream).

The complete flow is centrally managed by the orchestrator (`pipeline.py`) in four sequential phases:

```
                  ┌──────────────────────────────────────────────┐
                  │   Phase 0: Upstream Secret & Endpoint Scan   │
                  │   agent-analyst (Team 3, port 8000)          │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         │  (Structured JSON Context)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │           Phase 1: Surface Discovery         │
                  │           Active Scout ReAct Agent           │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         │  (Natural Language Context)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │       Phase 2: Targeted Vulnerability Scan   │
                  │       Active Analyst ReAct Agent             │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         │  (Structured Candidates Payload)
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │    Phase 3: Exploitation & PoC Verification   │
                  │    agent-striker (Team 5, port 8005)         │
                  └──────────────────────────────────────────────┘
```

---

## 2. API Integration & Handoff Contracts

To support decoupled agent design, all boundaries are crossed using **honest summaries and structured parameters** rather than passing raw scanner logs.

### Upstream: Analyst $\rightarrow$ Prober (Team 3 $\rightarrow$ Team 4)
- **Endpoint:** `POST http://localhost:8000/agents/agent-analyst/tasks`
- **Request payload:** Contains target and instructions for finding credentials and exposed paths.
- **Contract translation:** We run `call_upstream_analyst()` to fetch their findings. Our `format_upstream_context()` transforms the raw findings into an injected context string that enriches the Prober's prompt. 
- **Effect:** If Team 3 flags a secret file at `/.git/config` or a live endpoint at `/api/v1/users`, this information is injected into the Prober Analyst's context, causing the agent to execute targeted scans (like `corsy` and `kxss`) on those exact locations.

### Downstream: Prober $\rightarrow$ Striker (Team 4 $\rightarrow$ Team 5)
- **Endpoint:** `POST http://localhost:8005/agents/agent-striker/tasks`
- **Request payload:** The `context` section strictly follows the structured format requested by the Striker team:
  ```json
  {
    "summary": "Plain-text summary of active scan findings & upstream secrets.",
    "findings": [
      {
        "type": "sqli_candidate" | "xss_candidate" | "ssrf_candidate" | "ssti_candidate",
        "url": "https://demo.testfire.net/search.aspx?q=test",
        "param": "q"
      }
    ]
  }
  ```
- **Contract translation:** Our `build_striker_context()` parses active scanner findings (e.g. `kxss` outputs, `nuclei` template detections) and extracts the exact `url` and `param` using URL parameter parsers.
- **Effect:** Striker receives targeted candidates (like `xss_candidate` at `/search.aspx` on parameter `q`), allowing its `sqlmap` or `dalfox` exploit tools to target the parameter directly without having to blindly guess inputs.

---

## 3. Graceful Degradation & State Guarding

The orchestrator enforces robust error boundaries to prevent cascading pipeline failures:

1. **Upstream Unreachable:** If the Team 3 endpoint (`http://localhost:8000`) is offline, the client catches the connection error and returns a status of `unreachable`. The pipeline degrades gracefully and continues the scan using only local active discovery.
2. **Downstream Unreachable:** If the Team 5 endpoint (`http://localhost:8005`) is offline, the client returns `unreachable`. The scan completes successfully, saving all local findings and logging the downstream communication failure.
3. **Scout Failure (Kill Mode):** If the Scout agent fails or times out, the orchestrator sets `target_live=False` and `scout_status="timeout"`. The Analyst agent detects this failure block in the context and uses Python-level early-exit state guarding to halt immediately, preventing unneeded tool executions.

---

## 4. How to Run & Verify

All modes can be run offline using the deterministic mock engines:

```bash
# 1. Happy Path — executes all 4 phases with mock context
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker -o pipeline_happy.json

# 2. Kill Mode — Scout fails, downstream is notified, scanning stops safely
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker --break-mode kill -o pipeline_kill.json

# 3. Garbage Mode — Scout receives invalid target, reports ground-truth mismatch
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker --break-mode garbage -o pipeline_garbage.json

# 4. Delay Mode — Inject 5s orchestrator delay to verify timing tracking
python pipeline.py --target https://demo.testfire.net --mock-llm --mock-upstream --mock-striker --break-mode delay -o pipeline_delay.json
```
