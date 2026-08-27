from app.models.schemas import SourceType, TrustLevel

_TRUST_MAP = {
    SourceType.USER: TrustLevel.TRUSTED,
    SourceType.API: TrustLevel.SEMI_TRUSTED,
    SourceType.AGENT_MEMORY: TrustLevel.SEMI_TRUSTED,
    SourceType.TOOL_OUTPUT: TrustLevel.SEMI_TRUSTED,
    SourceType.EXTERNAL_DOCUMENT: TrustLevel.UNTRUSTED,
}


def resolve_trust_level(source: SourceType) -> TrustLevel:
    """Untrusted-by-default: unmapped sources fail closed, not open."""
    return _TRUST_MAP.get(source, TrustLevel.UNTRUSTED)