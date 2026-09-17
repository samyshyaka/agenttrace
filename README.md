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