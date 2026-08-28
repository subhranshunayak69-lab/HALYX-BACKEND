from typing import Any, Callable, Dict, Optional, Tuple

from app.models.schemas import Decision, SourceType, ThreatType, TrustLevel
from app.security import detector, policy, risk, trust
from app.tools.registry import execute_tool


def run_security_check(
    agent_id: str,
    source: SourceType,
    content: str,
    tool: str,
    arguments: Optional[Dict[str, Any]] = None,
) -> Tuple[Decision, float, ThreatType, TrustLevel, list]:
    """Runs in-process security evaluation pipeline."""
    args = arguments or {}
    trust_level = trust.resolve_trust_level(source)
    detection = detector.detect(content, tool=tool, arguments=args)
    risk_score, reasons = risk.score(
        trust_level=trust_level,
        detection=detection,
        tool=tool,
        arguments=args,
    )
    decision = policy.decide(risk_score)
    return decision, risk_score, detection.threat_type, trust_level, reasons


def intercept_tool_call(
    agent_id: str,
    source: SourceType,
    content: str,
    tool: str,
    arguments: Optional[Dict[str, Any]] = None,
    human_approval_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
) -> Dict[str, Any]:
    """Evaluates security rules and executes tool if permitted."""
    args = arguments or {}
    decision, risk_score, threat_type, trust_level, reasons = run_security_check(
        agent_id, source, content, tool, args
    )

    report = {
        "agent_id": agent_id,
        "tool": tool,
        "arguments": args,
        "decision": decision,
        "risk_score": risk_score,
        "threat_type": threat_type,
        "trust_level": trust_level,
        "reasons": reasons,
    }

    if decision == Decision.BLOCK:
        report["execution"] = {"status": "blocked", "message": "Tool call blocked."}
        return report

    if decision == Decision.REVIEW:
        approved = human_approval_fn(report) if human_approval_fn else False
        if not approved:
            report["execution"] = {
                "status": "rejected_by_human",
                "message": "Human reviewer denied the request.",
            }
            return report

    report["execution"] = execute_tool(tool, args)
    return report
