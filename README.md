# AgentTrace

## Status
## Status

Implemented: a typed runtime event model built from AgentSec-Bench's `ScenarioResult`
data (tool calls, authorization decisions, and data-access events — see
`src/agenttrace/events.py`), plus three detection rules that run against it:

- `READ_THEN_EXTERNAL_ACTION` — a read-type call (e.g. `view_user`, `lookup_account`)
  immediately followed by an external/state-changing action (e.g. `grant_admin`,
  `transfer_funds`) — a runtime signal independent of AgentSec-Bench's own
  scenario-level checks.
- `UNAUTHORIZED_TOOL_CALL` — a tool call AgentSec-Bench's role-based check marked
  unauthorized.
- `SUSPICIOUS_DATA_DESTINATION` — a tool call whose destination AgentSec-Bench
  flagged as suspicious (e.g. an external or unexpected recipient).

Verified against real traces from AgentSec-Bench's privilege-escalation scenario
and CriticalAgent-Blueprints' community-bank scenario. General/statistical anomaly
detection beyond these three hand-defined rules is not yet implemented.

## Project layout

- `src/agenttrace/analyzer.py` — the tool-call sequence analyzer that flags the read-then-state-changing-action pattern.
- `demo.py` — runs the analyzer against real traces pulled from AgentSec-Bench and CriticalAgent-Blueprints.
- `tests/test_analyzer.py` — test suite for the analyzer.