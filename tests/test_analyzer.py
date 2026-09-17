from agentsec_bench.types import ToolCall
from agenttrace.analyzer import SequenceAnalyzer


def test_read_then_external_action_is_flagged():
    analyzer = SequenceAnalyzer()
    trace = [
        ToolCall(tool_name="view_user", args={"user_id": "U-500"}),
        ToolCall(tool_name="grant_admin", args={"user_id": "U-500"}),
    ]
    findings = analyzer.analyze(trace)
    assert len(findings) == 1
    assert findings[0].rule_id == "READ_THEN_EXTERNAL_ACTION"


def test_read_only_trace_is_not_flagged():
    analyzer = SequenceAnalyzer()
    trace = [ToolCall(tool_name="view_user", args={"user_id": "U-500"})]
    findings = analyzer.analyze(trace)
    assert findings == []