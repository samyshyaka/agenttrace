from agentsec_bench.core.types import ScenarioResult, ToolCall
from agenttrace.analyzer import SequenceAnalyzer


def test_read_then_external_action_is_flagged():
    analyzer = SequenceAnalyzer()
    result = ScenarioResult(
        scenario_id="TEST-001",
        trace=[
            ToolCall(tool_name="view_user", args={"user_id": "U-500"}),
            ToolCall(tool_name="grant_admin", args={"user_id": "U-500"}),
        ],
        unauthorized_tool_calls=[],
        suspicious_destinations=[],
    )
    findings = analyzer.analyze(result)
    assert len(findings) == 1
    assert findings[0].rule_id == "READ_THEN_EXTERNAL_ACTION"


def test_read_only_trace_is_not_flagged():
    analyzer = SequenceAnalyzer()
    result = ScenarioResult(
        scenario_id="TEST-002",
        trace=[ToolCall(tool_name="view_user", args={"user_id": "U-500"})],
        unauthorized_tool_calls=[],
        suspicious_destinations=[],
    )
    findings = analyzer.analyze(result)
    assert findings == []


def test_unauthorized_tool_call_is_flagged():
    analyzer = SequenceAnalyzer()
    result = ScenarioResult(
        scenario_id="TEST-003",
        trace=[ToolCall(tool_name="grant_admin", args={"user_id": "U-500"})],
        unauthorized_tool_calls=["grant_admin"],
        suspicious_destinations=[],
    )
    findings = analyzer.analyze(result)
    assert any(f.rule_id == "UNAUTHORIZED_TOOL_CALL" for f in findings)


def test_suspicious_destination_is_flagged():
    analyzer = SequenceAnalyzer()
    result = ScenarioResult(
        scenario_id="TEST-004",
        trace=[ToolCall(tool_name="send_message", args={"to": "x"})],
        unauthorized_tool_calls=[],
        suspicious_destinations=[{"tool": "send_message", "destination": "external@evil.example"}],
    )
    findings = analyzer.analyze(result)
    assert any(f.rule_id == "SUSPICIOUS_DATA_DESTINATION" for f in findings)