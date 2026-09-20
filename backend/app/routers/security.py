"""
Security Dashboard API Router — event history, request traces, and statistics.
All data comes from actual SQLite records, never fabricated.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import List, Optional

from app.database import get_db
from app.models.request_log import RequestLog
from app.models.security_event import SecurityEvent
from app.models.layer_result import LayerResult
from app.schemas.security import SecurityEventSchema, RequestTraceSchema, SecurityStatsSchema

router = APIRouter(prefix="/api/security", tags=["security"])


@router.get("/events", response_model=List[SecurityEventSchema])
async def get_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Paginated security event history from SQLite."""
    query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))
    if event_type:
        query = query.where(SecurityEvent.event_type == event_type)
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    events = result.scalars().all()
    return [SecurityEventSchema.model_validate(e) for e in events]


@router.get("/events/{event_id}", response_model=SecurityEventSchema)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    """Single event detail."""
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.id == event_id))
    event = result.scalar_one_or_none()
    if not event:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Event not found")
    return SecurityEventSchema.model_validate(event)


@router.get("/requests", response_model=List[dict])
async def get_requests(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Paginated request log history."""
    query = select(RequestLog).order_by(desc(RequestLog.timestamp))
    if decision:
        query = query.where(RequestLog.security_decision == decision)
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    requests = result.scalars().all()
    return [
        {
            "request_id": r.request_id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "user_prompt": r.user_prompt[:100] + "..." if len(r.user_prompt) > 100 else r.user_prompt,
            "security_decision": r.security_decision,
            "risk_score": r.risk_score,
            "confidence": r.confidence,
            "hard_block": r.hard_block,
            "total_latency_ms": r.total_latency_ms,
        }
        for r in requests
    ]


@router.get("/requests/{request_id}/trace", response_model=RequestTraceSchema)
async def get_request_trace(request_id: str, db: AsyncSession = Depends(get_db)):
    """Full request trace including all layer results and events."""
    # Get request log
    result = await db.execute(select(RequestLog).where(RequestLog.request_id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Request not found")

    # Get layer results
    lr_result = await db.execute(select(LayerResult).where(LayerResult.request_id == request_id))
    layer_results = lr_result.scalars().all()

    # Get events
    ev_result = await db.execute(
        select(SecurityEvent).where(SecurityEvent.request_id == request_id).order_by(SecurityEvent.timestamp)
    )
    events = ev_result.scalars().all()

    return RequestTraceSchema(
        request_id=req.request_id,
        timestamp=req.timestamp,
        user_prompt=req.user_prompt,
        security_decision=req.security_decision,
        risk_score=req.risk_score,
        confidence=req.confidence,
        hard_block=req.hard_block,
        decision_reason=req.decision_reason,
        triggered_layers=req.triggered_layers,
        llm_response=req.llm_response,
        was_output_safe=req.was_output_safe,
        total_latency_ms=req.total_latency_ms,
        layer_results=[
            {
                "layer_name": lr.layer_name,
                "passed": lr.passed,
                "score": lr.score,
                "details": lr.details,
                "latency_ms": lr.latency_ms,
                "evidence_type": getattr(lr, "evidence_type", "weak_anomaly") or "weak_anomaly",
                "hard_block_trigger": getattr(lr, "hard_block_trigger", False) or False,
            }
            for lr in layer_results
        ],
        events=[SecurityEventSchema.model_validate(e) for e in events],
    )


@router.get("/stats", response_model=SecurityStatsSchema)
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate statistics calculated from actual database records."""
    # Total requests
    total_result = await db.execute(select(func.count(RequestLog.id)))
    total = total_result.scalar() or 0

    # Decision counts
    allowed_result = await db.execute(
        select(func.count(RequestLog.id)).where(RequestLog.security_decision == "ALLOW")
    )
    allowed = allowed_result.scalar() or 0

    sanitized_result = await db.execute(
        select(func.count(RequestLog.id)).where(RequestLog.security_decision == "SANITIZE")
    )
    sanitized = sanitized_result.scalar() or 0

    blocked_result = await db.execute(
        select(func.count(RequestLog.id)).where(RequestLog.security_decision == "BLOCK")
    )
    blocked = blocked_result.scalar() or 0

    hard_block_result = await db.execute(
        select(func.count(RequestLog.id)).where(RequestLog.hard_block == True)
    )
    hard_blocks = hard_block_result.scalar() or 0

    # Average latency
    avg_latency_result = await db.execute(select(func.avg(RequestLog.total_latency_ms)))
    avg_latency = avg_latency_result.scalar() or 0.0

    # Average risk score
    avg_risk_result = await db.execute(select(func.avg(RequestLog.risk_score)))
    avg_risk = avg_risk_result.scalar() or 0.0

    # Layer trigger counts from layer_results where passed=False
    lr_result = await db.execute(
        select(LayerResult.layer_name, func.count(LayerResult.id))
        .where(LayerResult.passed == False)
        .group_by(LayerResult.layer_name)
    )
    layer_trigger_counts = {row[0]: row[1] for row in lr_result.all()}

    # Attack type counts from events
    attack_result = await db.execute(
        select(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .where(SecurityEvent.event_type == "REQUEST_BLOCKED")
        .group_by(SecurityEvent.event_type)
    )
    attack_type_counts = {row[0]: row[1] for row in attack_result.all()}

    return SecurityStatsSchema(
        total_requests=total,
        allowed_requests=allowed,
        sanitized_requests=sanitized,
        blocked_requests=blocked,
        hard_blocks=hard_blocks,
        avg_latency_ms=round(float(avg_latency), 2),
        avg_risk_score=round(float(avg_risk), 4),
        layer_trigger_counts=layer_trigger_counts,
        attack_type_counts=attack_type_counts,
    )
