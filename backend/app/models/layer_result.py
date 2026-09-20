"""
LayerResult model — stores individual detection results for each of the 6 firewall layers.
Dashboard displays these independently per request.
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base


class LayerResult(Base):
    __tablename__ = "layer_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), ForeignKey("request_logs.request_id"), nullable=False, index=True)
    layer_name = Column(String(64), nullable=False)
    passed = Column(Boolean, nullable=False)
    score = Column(Float, default=0.0)
    evidence_type = Column(String(32), default="weak_anomaly", nullable=True)
    hard_block_trigger = Column(Boolean, default=False, nullable=True)
    details = Column(JSON, nullable=True)
    latency_ms = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    request_log = relationship("RequestLog", back_populates="layer_results")
