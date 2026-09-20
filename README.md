# AgentTrace

## Status

Minimal version implemented. Logs and analyzes tool-call sequences using the
same `ToolCall` trace data already produced by AgentSec-Bench's evaluator.
Currently flags one hand-defined suspicious pattern — a read-type call
immediately followed by an external/state-changing action (e.g. `view_user`
→ `grant_admin`, `lookup_account` → `transfer_funds`) — as a runtime signal
independent of AgentSec-Bench's own scenario-level checks. Verified against
real traces from AgentSec-Bench's privilege-escalation scenario and
CriticalAgent-Blueprints' community-bank scenario. General anomaly detection
beyond this hand-defined rule is not yet implemented.

## Project layout

- `src/agenttrace/analyzer.py` — the tool-call sequence analyzer that flags the read-then-state-changing-action pattern.
- `demo.py` — runs the analyzer against real traces pulled from AgentSec-Bench and CriticalAgent-Blueprints.
- `tests/test_analyzer.py` — test suite for the analyzer.