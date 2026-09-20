import React, { useState } from 'react';
import LayerPipeline from './LayerPipeline';

/**
 * RequestTrace — Full forensic audit inspector for a single request.
 * Displays:
 *  - Request Metadata (ID, user prompt, decision, risk score, confidence, latency)
 *  - Vertical 6-Layer Pipeline visualization with details
 *  - Chronological Event Timeline for this request
 */
export default function RequestTrace({ trace, onClose }) {
  const [activeTab, setActiveTab] = useState('pipeline'); // 'pipeline' | 'events' | 'prompt'

  if (!trace) return null;

  const {
    request_id,
    user_prompt,
    security_decision,
    risk_score,
    confidence,
    hard_block,
    total_latency_ms,
    decision_reason,
    triggered_layers,
    layer_results,
    events,
  } = trace;

  const decisionClass = security_decision?.toLowerCase() || 'allow';
  const riskPercent = (risk_score * 100).toFixed(1);
  const confidencePercent = confidence != null ? (confidence * 100).toFixed(0) : 'N/A';

  return (
    <div className="request-trace-modal-container">
      <div className="trace-card">
        {/* Header Strip */}
        <div className="trace-header">
          <div className="trace-title-group">
            <span className="trace-icon">🔬</span>
            <div className="trace-title-col">
              <div className="trace-title-row">
                <span className="trace-heading">FORENSIC REQUEST AUDIT</span>
                <span className={`trace-badge-decision badge-${decisionClass}`}>
                  {security_decision === 'ALLOW' && '✓ ALLOWED'}
                  {security_decision === 'BLOCK' && '✕ BLOCKED'}
                  {security_decision === 'SANITIZE' && '⚠ SANITIZED'}
                </span>
                {hard_block && <span className="trace-hard-block-tag">HARD BLOCK TRIGGERED</span>}
              </div>
              <span className="trace-id-label">REQUEST ID: <code>{request_id}</code></span>
            </div>
          </div>
          {onClose && (
            <button className="trace-close-btn" onClick={onClose} title="Close inspector">
              ✕
            </button>
          )}
        </div>

        {/* Telemetry Summary Bar */}
        <div className="trace-summary-strip">
          <div className="summary-item">
            <span className="item-label">RISK SCORE</span>
            <span className={`item-value ${risk_score >= 0.75 ? 'val-danger' : risk_score >= 0.45 ? 'val-warn' : 'val-safe'}`}>
              {riskPercent}%
            </span>
          </div>

          <div className="summary-item">
            <span className="item-label">CONFIDENCE</span>
            <span className="item-value">{confidencePercent}%</span>
          </div>

          <div className="summary-item">
            <span className="item-label">TOTAL DEFENSE LATENCY</span>
            <span className="item-value mono">{total_latency_ms?.toFixed(1) || 0} ms</span>
          </div>

          <div className="summary-item">
            <span className="item-label">HARD BLOCK</span>
            <span className={`item-value ${hard_block ? 'val-danger' : 'val-safe'}`}>
              {hard_block ? 'YES' : 'NO'}
            </span>
          </div>
        </div>

        {/* Reason / Trigger Banner */}
        {decision_reason && (
          <div className={`trace-reason-banner reason-${decisionClass}`}>
            <span className="reason-icon">{security_decision === 'ALLOW' ? '🛡️' : '🚨'}</span>
            <div className="reason-text">
              <strong>DECISION RATIONALE:</strong> {decision_reason}
            </div>
          </div>
        )}

        {/* Triggered Layers Pill List */}
        {triggered_layers && triggered_layers.length > 0 && (
          <div className="trace-triggers-row">
            <span className="triggers-label">FLAGGED EVIDENCE LAYERS:</span>
            <div className="triggers-tags">
              {triggered_layers.map((l, i) => (
                <span key={i} className="trigger-tag-item">⚡ {l}</span>
              ))}
            </div>
          </div>
        )}

        {/* Tabs for Navigation */}
        <div className="trace-nav-tabs">
          <button
            className={`trace-tab-btn ${activeTab === 'pipeline' ? 'active' : ''}`}
            onClick={() => setActiveTab('pipeline')}
          >
            🛡️ 6-Layer Audit ({layer_results?.length || 0})
          </button>
          <button
            className={`trace-tab-btn ${activeTab === 'prompt' ? 'active' : ''}`}
            onClick={() => setActiveTab('prompt')}
          >
            💬 Inspected Prompt
          </button>
          <button
            className={`trace-tab-btn ${activeTab === 'events' ? 'active' : ''}`}
            onClick={() => setActiveTab('events')}
          >
            ⏱ Chronological Trace Events ({events?.length || 0})
          </button>
        </div>

        {/* Tab Content */}
        <div className="trace-content-body">
          {activeTab === 'pipeline' && (
            <div className="trace-pipeline-view">
              <LayerPipeline layers={layer_results} variant="vertical" />
            </div>
          )}

          {activeTab === 'prompt' && (
            <div className="trace-prompt-view">
              <div className="prompt-meta-info">
                <span>RAW USER INPUT CAPTURED AT INGRESS GATEWAY:</span>
              </div>
              <div className="prompt-code-box">
                <pre>{user_prompt || '(No prompt captured)'}</pre>
              </div>
            </div>
          )}

          {activeTab === 'events' && (
            <div className="trace-events-view">
              {(!events || events.length === 0) ? (
                <div className="no-events-notice">No individual trace events recorded for this request.</div>
              ) : (
                <div className="trace-timeline">
                  {events.map((evt, idx) => (
                    <div key={idx} className="timeline-item">
                      <div className="timeline-marker" />
                      <div className="timeline-content">
                        <div className="timeline-header">
                          <span className="timeline-type">{evt.event_type}</span>
                          {evt.timestamp && (
                            <span className="timeline-time">
                              {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })}
                            </span>
                          )}
                        </div>
                        <div className="timeline-body">
                          {evt.layer_name && <span>Layer: <strong>{evt.layer_name}</strong> · </span>}
                          {evt.score != null && <span>Score: <strong>{(evt.score * 100).toFixed(1)}%</strong> · </span>}
                          {evt.latency_ms != null && <span>Latency: <strong>{evt.latency_ms.toFixed(2)}ms</strong></span>}
                          {evt.decision && <span>Decision: <strong>{evt.decision}</strong></span>}
                        </div>
                        {evt.details && Object.keys(evt.details).length > 0 && (
                          <pre className="timeline-json">{JSON.stringify(evt.details, null, 2)}</pre>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
