import json

from fastapi import APIRouter, Query

from app.database import AuditLog, get_all_logs, get_incidents, save_audit_log
from app.models.schemas import SecurityCheckRequest, SecurityCheckResponse
from app.security import detector, policy, risk, trust

router = APIRouter(prefix="/api/v1/security", tags=["security"])


@router.post("/check", response_model=SecurityCheckResponse)
def check_security(request: SecurityCheckRequest) -> SecurityCheckResponse:
    args = request.arguments or {}

    trust_level = trust.resolve_trust_level(request.source)
    detection = detector.detect(
        request.content,
        tool=request.tool,
        arguments=args,
    )
    risk_score, reasons = risk.score(
        trust_level=trust_level,
        detection=detection,
        tool=request.tool,
        arguments=args,
    )
    decision = policy.decide(risk_score)

    log_entry = AuditLog(
        agent_id=request.agent_id,
        source=request.source.value,
        content=request.content,
        tool=request.tool,
        arguments=json.dumps(args),
        decision=decision.value,
        risk_score=risk_score,
        threat_type=detection.threat_type.value,
        trust_level=trust_level.value,
        reasons=json.dumps(reasons),
        layers_triggered=json.dumps(detection.layers_triggered),
    )
    save_audit_log(log_entry)

    return SecurityCheckResponse(
        decision=decision,
        risk_score=risk_score,
        threat_type=detection.threat_type,
        trust_level=trust_level,
        reasons=reasons,
    )


@router.get("/logs")
def list_logs(limit: int = Query(default=100, ge=1, le=1000)):
    return get_all_logs(limit=limit)


@router.get("/incidents")
def list_incidents(limit: int = Query(default=100, ge=1, le=1000)):
    return get_incidents(limit=limit)
