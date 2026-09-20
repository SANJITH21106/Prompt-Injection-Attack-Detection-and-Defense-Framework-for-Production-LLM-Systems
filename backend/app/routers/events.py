"""
SSE Event Stream Router — GET /api/events/stream
Streams real-time pipeline events to the Security Dashboard.
Uses sse-starlette for proper SSE protocol handling.
"""

import asyncio
import json
from fastapi import APIRouter, Request
from sse_starlette.sse import EventSourceResponse
from app.services.event_bus import event_bus

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("/stream")
async def event_stream(request: Request):
    """
    SSE endpoint for real-time security pipeline events.
    Each connected dashboard client gets its own subscription.
    """
    queue = event_bus.subscribe()

    async def generate():
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                try:
                    # Wait for next event with timeout for keepalive
                    event_data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield {
                        "event": "security_event",
                        "data": event_data,
                    }
                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield {
                        "event": "ping",
                        "data": json.dumps({"type": "keepalive"}),
                    }
        finally:
            event_bus.unsubscribe(queue)

    return EventSourceResponse(generate())
