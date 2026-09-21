"""Normalized event schema for AgentTrace.

AgentSec-Bench's ScenarioResult exposes more than a flat tool-call trace --
it also carries unauthorized_tool_calls and suspicious_destinations. This
module turns all of that into a typed stream of runtime events (tool
calls, authorization decisions, data-access events) that detection rules
can reason about uniformly, rather than re-deriving this structure ad hoc
per rule.
"""
from dataclasses import dataclass, field
from typing import Any
from agentsec_bench.core.types import ScenarioResult


@dataclass
class ToolCallEvent:
    """A single tool invocation, in call order."""
    index: int
    tool_name: str
    args: dict[str, Any]


@dataclass
class AuthorizationEvent:
    """Whether a given tool call was authorized, per AgentSec-Bench's
    role-based check."""
    tool_name: str
    authorized: bool


@dataclass
class DataAccessEvent:
    """A tool call whose destination was flagged as suspicious."""
    tool_name: str
    destination: str


@dataclass
class TraceEvents:
    """The full normalized event set for one scenario run."""
    scenario_id: str
    tool_calls: list[ToolCallEvent] = field(default_factory=list)
    authorization_events: list[AuthorizationEvent] = field(default_factory=list)
    data_access_events: list[DataAccessEvent] = field(default_factory=list)


def build_events(result: ScenarioResult) -> TraceEvents:
    """Normalize a ScenarioResult into a typed TraceEvents stream."""
    tool_calls = [
        ToolCallEvent(index=i, tool_name=c.tool_name, args=c.args)
        for i, c in enumerate(result.trace)
    ]

    unauthorized = set(result.unauthorized_tool_calls)
    authorization_events = [
        AuthorizationEvent(tool_name=c.tool_name, authorized=c.tool_name not in unauthorized)
        for c in result.trace
    ]

    data_access_events = [
        DataAccessEvent(tool_name=d.get("tool", ""), destination=d.get("destination", ""))
        for d in result.suspicious_destinations
    ]

    return TraceEvents(
        scenario_id=result.scenario_id,
        tool_calls=tool_calls,
        authorization_events=authorization_events,
        data_access_events=data_access_events,
    )