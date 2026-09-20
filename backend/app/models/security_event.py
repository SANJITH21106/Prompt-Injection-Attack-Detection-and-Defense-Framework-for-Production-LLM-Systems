"""
SecurityEvent model — records each pipeline event (LAYER_STARTED, SECURITY_DECISION, etc.)
for real-time SSE streaming and audit trail.
"""

from sqlalchemy import Column, Integer, String, Float, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), ForeignKey("request_logs.request_id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    event_type = Column(String(64), nullable=False)  # REQUEST_RECEIVED, LAYER_STARTED, etc.
    severity = Column(String(16), nullable=True)  # LOW / MEDIUM / HIGH / CRITICAL
    layer_name = Column(String(64), nullable=True)
    status = Column(String(32), nullable=True)
    details = Column(JSON, nullable=True)
    score = Column(Float, nullable=True)
    latency_ms = Column(Float, nullable=True)

    # Relationship
    request_log = relationship("RequestLog", back_populates="security_events")
