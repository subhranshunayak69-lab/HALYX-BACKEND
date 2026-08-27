"""
Halyx — Gateway Interceptor
This is the enforcement point. Every tool call an agent wants to make
passes through here FIRST. Halyx's security core decides ALLOW / REVIEW /
BLOCK, and only ALLOW (or an approved REVIEW) reaches the real tool.
"""

from app.models.schemas import SecurityCheckRequest, Decision, SourceType
from app.security import trust, detector, risk, policy
from app.tools.registry import execute_tool


def run_security_check(
    agent_id: str,
    source: SourceType,
    content: str,
    tool: str,
    arguments: dict,
):
    """Runs the same pipeline as the /security/check API endpoint,
    but called directly in-process (no HTTP round trip needed)."""
    trust_level = trust.resolve_trust_level(source)
    detection = detector.detect(content, tool=tool, arguments=arguments)
    risk_score, reasons = risk.score(
        trust_level=trust_level,
        detection=detection,
        tool=tool,
        arguments=arguments,
    )
    decision = policy.decide(risk_score)
    return decision, risk_score, detection.threat_type, trust_level, reasons


def intercept_tool_call(
    agent_id: str,
    source: SourceType,
    content: str,
    tool: str,
    arguments: dict,
    human_approval_fn=None,
):
    """
    The core enforcement function.

    - ALLOW  -> tool runs immediately
    - REVIEW -> pauses and asks a human (via human_approval_fn) before running
    - BLOCK  -> tool never runs, request is rejected outright
    """
    decision, risk_score, threat_type, trust_level, reasons = run_security_check(
        agent_id, source, content, tool, arguments
    )

    report = {
        "agent_id": agent_id,
        "tool": tool,
        "arguments": arguments,
        "decision": decision,
        "risk_score": risk_score,
        "threat_type": threat_type,
        "trust_level": trust_level,
        "reasons": reasons,
    }

    if decision == Decision.BLOCK:
        report["execution"] = {"status": "blocked", "message": "Tool call blocked by Halyx."}
        return report

    if decision == Decision.REVIEW:
        approved = human_approval_fn(report) if human_approval_fn else False
        if not approved:
            report["execution"] = {"status": "rejected_by_human", "message": "Human reviewer denied the request."}
            return report
        # fall through to execution if approved

    # ALLOW, or REVIEW that got human approval
    result = execute_tool(tool, arguments)
    report["execution"] = result
    return report