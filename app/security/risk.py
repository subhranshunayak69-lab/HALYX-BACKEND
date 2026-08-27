from typing import List, Tuple

from app.models.schemas import TrustLevel
from app.security.detector import DetectionResult

_SENSITIVE_TOOLS = {"send_email", "delete_file", "make_payment", "run_shell", "http_request"}

_TRUST_WEIGHT = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.SEMI_TRUSTED: 15,
    TrustLevel.UNTRUSTED: 30,
}


def score(
    trust_level: TrustLevel,
    detection: DetectionResult,
    tool: str | None,
    arguments: dict,
) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    total = 0

    trust_contribution = _TRUST_WEIGHT[trust_level]
    total += trust_contribution
    if trust_level == TrustLevel.UNTRUSTED:
        reasons.append("Instruction originated from untrusted content")
    elif trust_level == TrustLevel.SEMI_TRUSTED:
        reasons.append("Instruction originated from a semi-trusted source")

    total += detection.injection_score
    if detection.matched_patterns:
        reasons.append(f"Detected {len(detection.matched_patterns)} suspicious language pattern(s)")

    if tool and tool in _SENSITIVE_TOOLS:
        total += 20
        reasons.append(f"Sensitive tool requested: '{tool}'")

    if arguments:
        arg_blob = " ".join(str(v) for v in arguments.values()).lower()
        if any(term in arg_blob for term in ["secret", "password", "credential", "token", ".env"]):
            total += 15
            reasons.append("Sensitive file or credential referenced in tool arguments")
        if tool == "send_email" and "recipient" in arguments:
            reasons.append("External communication requested")

    return min(total, 100), reasons