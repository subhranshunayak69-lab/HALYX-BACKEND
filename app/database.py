from datetime import datetime, timezone
from typing import List, Optional

from sqlmodel import Field, Session, SQLModel, create_engine, select

DATABASE_URL = "sqlite:///halyx.db"
engine = create_engine(DATABASE_URL, echo=False)


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=get_utc_now)

    agent_id: str
    source: str
    content: str
    tool: Optional[str] = None
    arguments: str = "{}"

    decision: str
    risk_score: int
    threat_type: str
    trust_level: str
    reasons: str = "[]"

    layers_triggered: str = "[]"


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def save_audit_log(entry: AuditLog) -> AuditLog:
    with Session(engine) as session:
        session.add(entry)
        session.commit()
        session.refresh(entry)
        return entry


def get_all_logs(limit: int = 100) -> List[AuditLog]:
    with Session(engine) as session:
        statement = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        return list(session.exec(statement).all())


def get_incidents(limit: int = 100) -> List[AuditLog]:
    with Session(engine) as session:
        statement = (
            select(AuditLog)
            .where(AuditLog.decision.in_(["BLOCK", "REVIEW"]))
            .order_by(AuditLog.id.desc())
            .limit(limit)
        )
        return list(session.exec(statement).all())
