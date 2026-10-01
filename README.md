# AgentTrace

## Status

Implemented: a typed runtime event model built from AgentSec-Bench's `ScenarioResult`
data (tool calls, authorization decisions, and data-access events - see
`src/agenttrace/events.py`), plus four detection rules that run against it:

- `READ_THEN_EXTERNAL_ACTION` - a read-type call (e.g. `view_user`, `lookup_account`)
  immediately followed by an external/state-changing action (e.g. `grant_admin`,
  `transfer_funds`) - a runtime signal independent of AgentSec-Bench's own
  scenario-level checks.
- `UNAUTHORIZED_TOOL_CALL` - a tool call AgentSec-Bench's role-based check marked
  unauthorized.
- `SUSPICIOUS_DATA_DESTINATION` - a tool call whose destination AgentSec-Bench
  flagged as suspicious (e.g. an external or unexpected recipient).
- `EXCESSIVE_TOOL_FREQUENCY` - a tool called an unusually high number of times in a
  single run (configurable threshold, default: more than 3 calls) - catches runaway
  loops or repeated exploitation attempts that a single-pass sequence check would miss.

Verified against real traces from AgentSec-Bench's privilege-escalation scenario
and CriticalAgent-Blueprints' community-bank scenario. General/statistical anomaly
detection beyond these four hand-defined rules is not yet implemented.

## Project layout

- `src/agenttrace/events.py` - normalizes AgentSec-Bench's `ScenarioResult` into a typed stream of tool-call, authorization, and data-access events.
- `src/agenttrace/analyzer.py` - the `SequenceAnalyzer`, which runs all detection rules against that event stream.
- `scripts/demo.py` - runs the analyzer against real traces pulled from AgentSec-Bench and CriticalAgent-Blueprints.
- `tests/test_analyzer.py` - test suite for the analyzer.