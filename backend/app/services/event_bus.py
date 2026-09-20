"""
In-memory async event bus for SSE broadcasting.
Each connected SSE client gets its own asyncio.Queue.
Events are broadcast to ALL subscribers simultaneously.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, Set


class EventBus:
    """Manages SSE subscriber queues and broadcasts pipeline events."""

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        """Register a new SSE subscriber. Returns the queue to consume from."""
        queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        """Remove an SSE subscriber."""
        self._subscribers.discard(queue)

    async def publish(self, event_type: str, **data):
        """Broadcast an event to all subscribers."""
        event = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **data,
        }
        event_str = json.dumps(event, default=str)
        dead_queues = []

        for queue in self._subscribers:
            try:
                queue.put_nowait(event_str)
            except asyncio.QueueFull:
                dead_queues.append(queue)

        # Remove dead/full queues
        for q in dead_queues:
            self._subscribers.discard(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Singleton event bus
event_bus = EventBus()
