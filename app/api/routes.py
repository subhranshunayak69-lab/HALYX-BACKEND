"""
Halyx — API Routes
Exposes POST /api/v1/security/check (wired to trust -> detector -> risk ->
policy, and now logs every decision), plus GET endpoints to view the
audit trail and incident history.
"""

import json

from fastapi import APIRouter

from app.models.schemas import SecurityCheckRequest, SecurityCheckResponse
from app.security import trust, detector, risk, policy
from app.database import AuditLog, save_audit_log, get_all_logs, get_incidents

router = APIRouter(prefix="/api/v1/security", tags=["security"])


@router.post("/check", response_model=SecurityCheckResponse)
def check(request: SecurityCheckRequest) -> SecurityCheckResponse:
    trust_level = trust.resolve_trust_level(request.source)
    detection = detector.detect(request.content, tool=request.tool, arguments=request.arguments or {})
    risk_score, reasons = risk.score(
        trust_level=trust_level,
        detection=detection,
        tool=request.tool,
        arguments=request.arguments or {},
    )
    decision = policy.decide(risk_score)

    # Persist every check as an audit log entry — this is what powers
    # the incident list and, later, the dashboard.
    save_audit_log(
        AuditLog(
            agent_id=request.agent_id,
            source=request.source.value,
            content=request.content,
            tool=request.tool,
            arguments=json.dumps(request.arguments or {}),
            decision=decision.value,
            risk_score=risk_score,
            threat_type=detection.threat_type.value,
            trust_level=trust_level.value,
            reasons=json.dumps(reasons),
            layers_triggered=json.dumps(detection.layers_triggered),
        )
    )

    return SecurityCheckResponse(
        decision=decision,
        risk_score=risk_score,
        threat_type=detection.threat_type,
        trust_level=trust_level,
        reasons=reasons,
    )


@router.get("/logs")
def logs(limit: int = 100):
    """Returns the full audit trail — every check ever made, newest first."""
    return get_all_logs(limit=limit)


@router.get("/incidents")
def incidents(limit: int = 100):
    """Returns only BLOCK and REVIEW events — the ones worth investigating."""
    return get_incidents(limit=limit)