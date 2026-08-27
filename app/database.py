"""
Halyx — Database Layer
SQLite via SQLModel (built on SQLAlchemy + Pydantic). Zero external
setup — creates a local halyx.db file automatically on first run.
Stores every security check as a permanent audit log entry.
"""

from datetime import datetime
from typing import List, Optional

from sqlmodel import Field, Session, SQLModel, create_engine, select

DATABASE_URL = "sqlite:///halyx.db"
engine = create_engine(DATABASE_URL, echo=False)


class AuditLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    agent_id: str
    source: str
    content: str
    tool: Optional[str] = None
    arguments: str = "{}"  # stored as JSON string for simplicity

    decision: str
    risk_score: int
    threat_type: str
    trust_level: str
    reasons: str = "[]"  # stored as JSON string

    layers_triggered: str = "[]"  # which detection layers fired


def init_db():
    """Creates the database file and tables if they don't already exist."""
    SQLModel.metadata.create_all(engine)


def save_audit_log(entry: AuditLog) -> AuditLog:
    with Session(engine) as session:
        session.add(entry)
        session.commit()
        session.refresh(entry)
        return entry


def get_all_logs(limit: int = 100) -> List[AuditLog]:
    with Session(engine) as session:
        statement = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
        return list(session.exec(statement))


def get_incidents(limit: int = 100) -> List[AuditLog]:
    """Returns only BLOCK and REVIEW decisions — the events worth a human's attention."""
    with Session(engine) as session:
        statement = (
            select(AuditLog)
            .where(AuditLog.decision.in_(["BLOCK", "REVIEW"]))
            .order_by(AuditLog.timestamp.desc())
            .limit(limit)
        )
        return list(session.exec(statement))