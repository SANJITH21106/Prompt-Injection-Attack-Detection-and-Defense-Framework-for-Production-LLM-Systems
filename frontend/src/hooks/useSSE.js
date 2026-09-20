import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * SSE event stream hook for real-time security events.
 * Connects to /api/events/stream and accumulates events.
 */
export function useSSE() {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef(null);

  const connect = useCallback(() => {
    if (sourceRef.current) {
      sourceRef.current.close();
    }

    const es = new EventSource('/api/events/stream');
    sourceRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => {
      setConnected(false);
      // Auto-reconnect is built into EventSource
    };

    es.addEventListener('security_event', (e) => {
      try {
        const data = JSON.parse(e.data);
        setEvents(prev => {
          const updated = [data, ...prev];
          return updated.slice(0, 200); // Keep last 200 events
        });
      } catch { /* ignore parse errors */ }
    });

    es.addEventListener('ping', () => {
      // Keepalive — no action needed
    });
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (sourceRef.current) {
        sourceRef.current.close();
      }
    };
  }, [connect]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, clearEvents };
}
