from app.models.schemas import Decision

BLOCK_THRESHOLD = 75
REVIEW_THRESHOLD = 30


def decide(risk_score: int) -> Decision:
    if risk_score >= BLOCK_THRESHOLD:
        return Decision.BLOCK
    if risk_score >= REVIEW_THRESHOLD:
        return Decision.REVIEW
    return Decision.ALLOW