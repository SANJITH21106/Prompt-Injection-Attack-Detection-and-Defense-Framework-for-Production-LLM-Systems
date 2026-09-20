import React, { useState, useMemo, useRef, useEffect } from 'react';

/**
 * LiveEventConsole — Real-time security event log powered by SSE stream.
 * Filter tabs: ALL, DECISIONS, LAYERS, THREATS.
 * Includes pause/resume stream auto-scroll, clear log, and event detail expansion.
 */
export default function LiveEventConsole({ events = [], connected = false, onClear }) {
  const [filter, setFilter] = useState('ALL'); // ALL | DECISION | LAYER | THREAT
  const [isPaused, setIsPaused] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState(null);
  const logEndRef = useRef(null);

  // Filter events based on active tab
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (filter === 'ALL') return true;
      if (filter === 'DECISION') return e.event_type === 'SECURITY_DECISION';
      if (filter === 'LAYER') {
        return e.event_type === 'LAYER_STARTED' || e.event_type === 'LAYER_COMPLETED';
      }
      if (filter === 'THREAT') {
        return e.event_type === 'REQUEST_BLOCKED' || (e.decision && e.decision !== 'ALLOW');
      }
      return true;
    });
  }, [events, filter]);

  // Auto-scroll when new events arrive and not paused
  useEffect(() => {
    if (!isPaused && logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, isPaused]);

  const getEventTagClass = (type, decision) => {
    if (type === 'REQUEST_BLOCKED' || decision === 'BLOCK') return 'tag-danger';
    if (type === 'SECURITY_DECISION' && decision === 'ALLOW') return 'tag-safe';
    if (type === 'SECURITY_DECISION' && decision === 'SANITIZE') return 'tag-warn';
    if (type === 'LAYER_COMPLETED') return 'tag-success';
    if (type === 'LAYER_STARTED') return 'tag-info';
    if (type?.includes('GEMINI')) return 'tag-purple';
    return 'tag-default';
  };

  return (
    <div className="live-event-console">
      <div className="console-toolbar">
        <div className="toolbar-left">
          <div className="console-title">
            <span className="console-terminal-icon">⚡</span>
            <span>LIVE EVENT STREAM</span>
            <span className="event-count-badge">{filteredEvents.length}</span>
          </div>
          <div className="stream-live-pill">
            <span className={`pulse-dot ${connected ? 'dot-active' : 'dot-inactive'}`} />
            <span>{connected ? 'STREAM ACTIVE' : 'RECONNECTING'}</span>
          </div>
        </div>

        <div className="toolbar-filters">
          {['ALL', 'DECISION', 'LAYER', 'THREAT'].map((tab) => (
            <button
              key={tab}
              className={`filter-tab-btn ${filter === tab ? 'active' : ''}`}
              onClick={() => setFilter(tab)}
            >
              {tab === 'ALL' ? 'All Events' : tab === 'DECISION' ? 'Decisions' : tab === 'LAYER' ? 'Layers' : 'Threats'}
            </button>
          ))}
        </div>

        <div className="toolbar-actions">
          <button
            className={`action-icon-btn ${isPaused ? 'btn-paused' : ''}`}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? 'Resume auto-scroll' : 'Pause auto-scroll'}
          >
            {isPaused ? '▶ Resume' : '⏸ Pause'}
          </button>
          {onClear && (
            <button
              className="action-icon-btn clear-btn"
              onClick={onClear}
              title="Clear event buffer"
            >
              🗑 Clear
            </button>
          )}
        </div>
      </div>

      <div className="console-stream-body">
        {filteredEvents.length === 0 ? (
          <div className="console-empty">
            <span className="empty-indicator">_</span>
            <span>Waiting for real-time firewall telemetry...</span>
          </div>
        ) : (
          filteredEvents.slice(0, 100).map((evt, idx) => {
            const key = evt.id || `${evt.request_id}-${idx}`;
            const isExpanded = expandedEventId === key;
            const timeStr = evt.timestamp
              ? new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
              : '--:--:--';

            return (
              <div
                key={key}
                className={`console-row ${getEventTagClass(evt.event_type, evt.decision)} ${isExpanded ? 'row-expanded' : ''}`}
                onClick={() => setExpandedEventId(isExpanded ? null : key)}
              >
                <div className="row-prefix">
                  <span className="row-time">{timeStr}</span>
                  <span className={`row-type-badge ${getEventTagClass(evt.event_type, evt.decision)}`}>
                    {evt.event_type}
                  </span>
                </div>

                <div className="row-message">
                  {evt.layer_name && (
                    <span className="row-layer-name">[{evt.layer_name}]</span>
                  )}
                  {evt.decision && (
                    <span className={`row-decision-val val-${evt.decision.toLowerCase()}`}>
                      DECISION: {evt.decision}
                    </span>
                  )}
                  {evt.score != null && (
                    <span className="row-score">Score: {(evt.score * 100).toFixed(1)}%</span>
                  )}
                  {evt.risk_score != null && (
                    <span className="row-risk">Risk: {(evt.risk_score * 100).toFixed(1)}%</span>
                  )}
                  {evt.latency_ms != null && (
                    <span className="row-latency">{evt.latency_ms.toFixed(1)}ms</span>
                  )}
                  {evt.status && (
                    <span className="row-status">Status: {evt.status}</span>
                  )}
                </div>

                {evt.request_id && (
                  <span className="row-req-id" title={evt.request_id}>
                    {evt.request_id.slice(0, 8)}
                  </span>
                )}

                {isExpanded && evt.details && Object.keys(evt.details).length > 0 && (
                  <div className="row-json-drawer">
                    <pre>{JSON.stringify(evt.details, null, 2)}</pre>
                  </div>
                )}
              </div>
            );
          })
        )}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
