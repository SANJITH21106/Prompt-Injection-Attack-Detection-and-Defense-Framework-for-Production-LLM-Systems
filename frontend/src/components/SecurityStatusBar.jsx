import React from 'react';

/**
 * SecurityStatusBar — Displays real-time security posture & metrics for the active session / last request.
 * Real backend values: decision, risk_score, latency, passed layers.
 */
export default function SecurityStatusBar({ security, layers, latencyMs, requestId, onOpenSidebar }) {
  const decision = security?.decision || 'STANDBY';
  const riskScore = security?.risk_score != null ? security.risk_score : 0;
  const hardBlock = security?.hard_block || false;
  
  // Calculate layer pass count from real layer results
  const totalLayers = layers?.length || 6;
  const passedLayers = layers ? layers.filter(l => l.passed).length : 6;
  const triggeredCount = security?.triggered_layers?.length || 0;

  let statusClass = 'status-standby';
  let statusText = 'FIREWALL ACTIVE';
  let statusIcon = '🛡️';

  if (decision === 'ALLOW') {
    statusClass = 'status-allow';
    statusText = 'VERIFIED SECURE';
    statusIcon = '✓';
  } else if (decision === 'BLOCK') {
    statusClass = 'status-block';
    statusText = hardBlock ? 'CRITICAL THREAT INTERCEPTED' : 'THREAT BLOCKED';
    statusIcon = '✕';
  } else if (decision === 'SANITIZE') {
    statusClass = 'status-sanitize';
    statusText = 'CONTENT SANITIZED';
    statusIcon = '⚠';
  }

  const riskPercent = (riskScore * 100).toFixed(1);
  const riskLevel = riskScore >= 0.75 ? 'danger' : riskScore >= 0.45 ? 'warn' : 'safe';

  return (
    <div className={`security-status-bar ${statusClass}`}>
      <div className="status-bar-left">
        {onOpenSidebar && (
          <button
            className="sidebar-inline-toggle-btn"
            onClick={onOpenSidebar}
            title="Open conversations sidebar"
            id="sidebar-inline-toggle"
          >
            <span className="toggle-icon">☰</span>
            <span className="toggle-text">Conversations</span>
          </button>
        )}
        <div className="status-badge-indicator">
          <span className="status-icon">{statusIcon}</span>
          <span className="status-text">{statusText}</span>
        </div>
        {requestId && (
          <span className="status-req-id" title={`Request ID: ${requestId}`}>
            REQ: {requestId.slice(0, 8)}
          </span>
        )}
      </div>

      <div className="status-bar-metrics">
        <div className="metric-pill" title="Firewall Pipeline Status">
          <span className="metric-label">PIPELINE</span>
          <span className={`metric-val ${passedLayers === totalLayers ? 'val-safe' : 'val-danger'}`}>
            {layers ? `${passedLayers}/${totalLayers} Passed` : '6-Layer Online'}
          </span>
        </div>

        <div className="metric-pill" title="Aggregate Threat Risk Score">
          <span className="metric-label">RISK</span>
          <div className="risk-meter-inline">
            <div
              className={`risk-meter-bar val-${riskLevel}`}
              style={{ width: `${Math.max(4, Math.min(100, riskScore * 100))}%` }}
            />
          </div>
          <span className={`metric-val val-${riskLevel}`}>{riskPercent}%</span>
        </div>

        {latencyMs != null && (
          <div className="metric-pill" title="Total Defense & Analysis Latency">
            <span className="metric-label">LATENCY</span>
            <span className="metric-val mono">{latencyMs.toFixed(0)}ms</span>
          </div>
        )}

        {triggeredCount > 0 && (
          <div className="metric-pill trigger-pill" title="Triggered Security Layers">
            <span className="metric-label">TRIGGERS</span>
            <span className="metric-val val-danger">{triggeredCount} Alert{triggeredCount > 1 ? 's' : ''}</span>
          </div>
        )}
      </div>
    </div>
  );
}
