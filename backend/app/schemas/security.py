"""Pydantic schemas for security dashboard API responses."""

from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime


class SecurityEventSchema(BaseModel):
    id: int
    request_id: str
    timestamp: datetime
    event_type: str
    severity: Optional[str] = None
    layer_name: Optional[str] = None
    status: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    score: Optional[float] = None
    latency_ms: Optional[float] = None

    model_config = {"from_attributes": True}


class RequestTraceSchema(BaseModel):
    request_id: str
    timestamp: datetime
    user_prompt: str
    security_decision: str
    risk_score: float
    confidence: float
    hard_block: bool
    decision_reason: Optional[str] = None
    triggered_layers: Optional[List[str]] = None
    llm_response: Optional[str] = None
    was_output_safe: Optional[bool] = None
    total_latency_ms: float
    layer_results: List[Dict[str, Any]]
    events: List[SecurityEventSchema]

    model_config = {"from_attributes": True}


class SecurityStatsSchema(BaseModel):
    total_requests: int
    allowed_requests: int
    sanitized_requests: int
    blocked_requests: int
    hard_blocks: int
    avg_latency_ms: float
    avg_risk_score: float
    layer_trigger_counts: Dict[str, int]
    attack_type_counts: Dict[str, int]
