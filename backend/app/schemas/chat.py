"""Pydantic schemas for chat request/response."""

from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class ChatRequest(BaseModel):
    prompt: str
    conversation_id: Optional[str] = None


class LayerResultSchema(BaseModel):
    layer_name: str
    passed: bool
    score: float
    details: Optional[Dict[str, Any]] = None
    latency_ms: float
    evidence_type: Optional[str] = "weak_anomaly"
    hard_block_trigger: Optional[bool] = False


class SecurityDecisionSchema(BaseModel):
    decision: str  # ALLOW / SANITIZE / BLOCK
    risk_score: float
    confidence: float
    reason: str
    hard_block: bool
    triggered_layers: List[str]


class ChatResponse(BaseModel):
    request_id: str
    response: Optional[str] = None
    security_decision: SecurityDecisionSchema
    layer_results: List[LayerResultSchema]
    total_latency_ms: float
    was_output_safe: Optional[bool] = None
