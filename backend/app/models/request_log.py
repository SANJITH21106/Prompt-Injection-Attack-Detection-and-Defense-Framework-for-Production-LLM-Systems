"""
RequestLog model — stores every chat request with its full security decision trace.
Uses SQLite-compatible types only (no JSONB, no PostgreSQL UUIDs).
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, Text, DateTime, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base


class RequestLog(Base):
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    user_prompt = Column(Text, nullable=False)
    sanitized_prompt = Column(Text, nullable=True)
    security_decision = Column(String(16), nullable=False)  # ALLOW / SANITIZE / BLOCK
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    hard_block = Column(Boolean, default=False)
    decision_reason = Column(Text, nullable=True)
    triggered_layers = Column(JSON, nullable=True)  # list of layer names
    llm_response = Column(Text, nullable=True)
    was_output_safe = Column(Boolean, nullable=True)
    total_latency_ms = Column(Float, default=0.0)

    # Relationships
    security_events = relationship("SecurityEvent", back_populates="request_log", cascade="all, delete-orphan")
    layer_results = relationship("LayerResult", back_populates="request_log", cascade="all, delete-orphan")
