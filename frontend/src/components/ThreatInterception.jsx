import React, { useState } from 'react';

/**
 * ThreatInterception — High-impact security alert panel rendered when a prompt is BLOCKED or SANITIZED.
 * Visually communicates real-time defense, attack containment, and layer-by-layer evidence.
 */
export default function ThreatInterception({ security, layers, requestId, userPrompt, onInspect }) {
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(false);

  const decision = security?.decision || 'BLOCK';
  const isHardBlock = security?.hard_block || false;
  const riskScore = security?.risk_score != null ? security.risk_score : 1.0;
  const reason = security?.reason || 'Adversarial pattern identified by active defense layers.';
  const triggeredLayers = security?.triggered_layers || [];

  const riskPercent = (riskScore * 100).toFixed(1);

  return (
    <div className={`threat-interception-card ${decision === 'BLOCK' ? 'block-variant' : 'sanitize-variant'}`}>
      <div className="interception-banner">
        <div className="banner-icon-col">
          <div className="alert-shield-icon">
            {decision === 'BLOCK' ? '🛡️✕' : '🛡️⚠'}
          </div>
        </div>
        <div className="banner-info-col">
          <div className="banner-top-row">
            <span className="banner-title">
              {decision === 'BLOCK'
                ? isHardBlock
                  ? 'CRITICAL ADVERSARIAL INJECTION INTERCEPTED'
                  : 'PROMPT INJECTION THREAT CONTAINED'
                : 'POTENTIAL RISK DETECTED — INPUT SANITIZED'}
            </span>
            <div className="banner-badges">
              {isHardBlock && <span className="badge-hard-block-tag">HARD BLOCK RULE</span>}
              <span className={`badge-decision ${decision.toLowerCase()}`}>{decision}</span>
            </div>
          </div>
          <p className="interception-summary">{reason}</p>
        </div>
      </div>

      <div className="interception-metrics-strip">
        <div className="metric-box">
          <span className="box-label">AGGREGATE RISK</span>
          <div className="risk-visual">
            <div className="risk-bar-track">
              <div
                className="risk-bar-danger"
                style={{ width: `${Math.max(5, Math.min(100, riskScore * 100))}%` }}
              />
            </div>
            <span className="box-val danger-text">{riskPercent}%</span>
          </div>
        </div>

        <div className="metric-box">
          <span className="box-label">INTERCEPTING LAYERS</span>
          <div className="trigger-tags-list">
            {triggeredLayers.length > 0 ? (
              triggeredLayers.map((layer, idx) => (
                <span key={idx} className="triggered-pill">
                  ⚡ {layer}
                </span>
              ))
            ) : (
              <span className="triggered-pill">Automated Firewall Evaluation</span>
            )}
          </div>
        </div>

        {requestId && (
          <div className="metric-box mono-box">
            <span className="box-label">TRACE ID</span>
            <span className="box-val mono-val">{requestId}</span>
          </div>
        )}
      </div>

      {layers && layers.length > 0 && (
        <div className="interception-expandable">
          <button
            className="details-toggle-btn"
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
          >
            <span>{showTechnicalDetails ? '▼ Hide Firewall Evidence' : '▶ Inspect Layer-by-Layer Evidence'}</span>
            <span className="details-layer-summary">
              {layers.filter(l => !l.passed).length} of {layers.length} Layers Flagged
            </span>
          </button>

          {showTechnicalDetails && (
            <div className="interception-details-body">
              <div className="flagged-layers-grid">
                {layers.map((layer, idx) => (
                  <div
                    key={idx}
                    className={`flagged-layer-cell ${layer.passed ? 'passed-cell' : 'flagged-cell'}`}
                  >
                    <div className="cell-header">
                      <span className="cell-name">L{idx + 1}: {layer.layer_name}</span>
                      <span className={`cell-tag ${layer.passed ? 'tag-clean' : 'tag-alert'}`}>
                        {layer.passed ? 'PASSED' : 'FLAGGED'}
                      </span>
                    </div>
                    <div className="cell-stats">
                      <span>Threat: {(layer.score * 100).toFixed(1)}%</span>
                      {layer.latency_ms != null && <span>⏱ {layer.latency_ms.toFixed(1)}ms</span>}
                    </div>
                    {layer.evidence_type && (
                      <div className="cell-evidence">Evidence: {layer.evidence_type}</div>
                    )}
                    {layer.details && Object.keys(layer.details).length > 0 && (
                      <pre className="cell-details-pre">
                        {JSON.stringify(layer.details, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="interception-footer">
        <span className="containment-notice">
          🔒 System integrity secured. Upstream LLM context was protected from unauthorized instruction override.
        </span>
        {onInspect && (
          <button className="soc-inspect-btn" onClick={() => onInspect(requestId)}>
            View in SOC Dashboard →
          </button>
        )}
      </div>
    </div>
  );
}
