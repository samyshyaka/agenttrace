# AgentTrace

Runtime behavioral monitoring and anomaly detection for AI agent tool-call sequences.

## Status

Architecture design phase. Not yet implemented.

AgentTrace is designed to log and analyze the sequence of tool calls an agent
makes during execution, using the same trace data already captured by
[AgentSec-Bench](https://github.com/samyshyaka/agentsec-bench)'s evaluator.
The goal is to flag unexpected call sequences (e.g. a read followed by an
unrelated external action) as a runtime signal, independent of the
scenario-level checks AgentSec-Bench already performs.

Implementation will begin with a minimal version: logging real tool-call
sequences and flagging one or two hand-defined suspicious patterns, before
expanding toward general anomaly detection.