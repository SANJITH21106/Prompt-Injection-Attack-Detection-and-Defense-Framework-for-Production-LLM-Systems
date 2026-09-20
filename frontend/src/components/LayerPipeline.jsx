import React, { useState } from 'react';

const DEFAULT_LAYERS = [
  { name: 'Rule-Based Detection', short: 'L1: Rules' },
  { name: 'SQL & Intent Analysis', short: 'L2: Intent/SQL' },
  { name: 'ML Safety Classifier', short: 'L3: ML Safety' },
  { name: 'Prompt-Injection Guardrails', short: 'L4: Guardrails' },
  { name: 'Chunk Anomaly Analysis', short: 'L5: Chunk Anomaly' },
  { name: 'Perplexity / Statistical Anomaly Analysis', short: 'L6: Perplexity' },
];

/**
 * LayerPipeline — Visualizes the 6-layer defense pipeline.
 * Props:
 *  - layers: Array of layer_results from backend API (or null)
 *  - variant: 'horizontal' (chat) | 'vertical' (dashboard / trace inspector)
 *  - isAnalyzing: boolean indicating real-time analysis in progress
 */
export default function LayerPipeline({ layers = null, variant = 'horizontal', isAnalyzing = false }) {
  const [expandedLayer, setExpandedLayer] = useState(null);

  // Map backend results to the standard 6 layers
  const pipelineData = DEFAULT_LAYERS.map((def, idx) => {
    const found = layers?.find(
      (l) => l.layer_name?.toLowerCase() === def.name.toLowerCase() ||
             l.layer_name?.toLowerCase().includes(def.name.toLowerCase().slice(0, 10))
    );

    if (found) {
      return {
        ...def,
        ...found,
        index: idx + 1,
        hasData: true,
      };
    }

    return {
      ...def,
      index: idx + 1,
      passed: true,
      score: 0,
      latency_ms: null,
      evidence_type: null,
      hard_block_trigger: false,
      details: null,
      hasData: false,
    };
  });

  const toggleExpand = (idx) => {
    setExpandedLayer(expandedLayer === idx ? null : idx);
  };

  if (variant === 'horizontal') {
    return (
      <div className="layer-pipeline-horizontal">
        <div className="pipeline-header-mini">
          <span className="pipeline-title">6-LAYER SECURITY PIPELINE</span>
          {isAnalyzing && <span className="pipeline-live-indicator"><span className="pulse-dot" /> EVALUATING</span>}
        </div>
        <div className="pipeline-track">
          {pipelineData.map((layer, i) => {
            const isFailed = layer.hasData && !layer.passed;
            const isHardBlock = layer.hard_block_trigger;
            const statusClass = isAnalyzing
              ? 'analyzing'
              : !layer.hasData
              ? 'idle'
              : isFailed
              ? (isHardBlock ? 'hard-block' : 'failed')
              : 'passed';

            return (
              <React.Fragment key={layer.name}>
                <div
                  className={`pipeline-node ${statusClass} ${expandedLayer === i ? 'selected' : ''}`}
                  onClick={() => toggleExpand(i)}
                  title={`${layer.name}: ${layer.hasData ? (layer.passed ? 'PASSED' : 'FAILED') : 'Ready'}`}
                >
                  <div className="node-badge">L{layer.index}</div>
                  <div className="node-content">
                    <span className="node-label">{layer.short}</span>
                    <div className="node-status-row">
                      {isAnalyzing ? (
                        <span className="node-status-eval">Scanning...</span>
                      ) : layer.hasData ? (
                        <>
                          <span className={`node-status-tag ${isFailed ? 'tag-fail' : 'tag-pass'}`}>
                            {isFailed ? 'TRIGGER' : 'CLEAR'}
                          </span>
                          <span className="node-score">
                            {(layer.score * 100).toFixed(0)}%
                          </span>
                        </>
                      ) : (
                        <span className="node-status-tag tag-idle">READY</span>
                      )}
                    </div>
                  </div>
                  {layer.latency_ms != null && (
                    <span className="node-latency">{layer.latency_ms.toFixed(1)}ms</span>
                  )}
                </div>
                {i < pipelineData.length - 1 && (
                  <div className={`pipeline-connector ${statusClass === 'passed' ? 'connector-active' : ''}`}>
                    <span className="connector-arrow">›</span>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Expandable detail card for horizontal view */}
        {expandedLayer !== null && pipelineData[expandedLayer] && (
          <div className="pipeline-detail-dropdown">
            <div className="dropdown-header">
              <strong>L{pipelineData[expandedLayer].index}: {pipelineData[expandedLayer].name}</strong>
              <button className="dropdown-close" onClick={() => setExpandedLayer(null)}>✕</button>
            </div>
            <div className="dropdown-body">
              <div className="dropdown-grid">
                <div><span>Status:</span> <strong className={pipelineData[expandedLayer].passed ? 'val-safe' : 'val-danger'}>
                  {pipelineData[expandedLayer].hasData ? (pipelineData[expandedLayer].passed ? 'PASSED' : 'FAILED / TRIGGERED') : 'Standby'}
                </strong></div>
                <div><span>Threat Score:</span> <strong>{(pipelineData[expandedLayer].score * 100).toFixed(1)}%</strong></div>
                <div><span>Latency:</span> <strong>{pipelineData[expandedLayer].latency_ms != null ? `${pipelineData[expandedLayer].latency_ms.toFixed(2)} ms` : 'N/A'}</strong></div>
                <div><span>Evidence Type:</span> <strong>{pipelineData[expandedLayer].evidence_type || 'None'}</strong></div>
              </div>
              {pipelineData[expandedLayer].details && (
                <div className="dropdown-json">
                  <pre>{JSON.stringify(pipelineData[expandedLayer].details, null, 2)}</pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }

  // Vertical Variant for Dashboard / Trace Inspector
  return (
    <div className="layer-pipeline-vertical">
      <div className="pipeline-vertical-list">
        {pipelineData.map((layer, i) => {
          const isFailed = layer.hasData && !layer.passed;
          const isHardBlock = layer.hard_block_trigger;
          const statusClass = !layer.hasData
            ? 'idle'
            : isFailed
            ? (isHardBlock ? 'hard-block' : 'failed')
            : 'passed';

          return (
            <div key={layer.name} className={`vertical-layer-item ${statusClass}`}>
              <div className="vertical-layer-header" onClick={() => toggleExpand(i)}>
                <div className="layer-index-circle">L{layer.index}</div>
                <div className="layer-main-info">
                  <div className="layer-title-row">
                    <span className="layer-full-name">{layer.name}</span>
                    <div className="layer-tags">
                      {isHardBlock && <span className="badge-hard-block">HARD BLOCK</span>}
                      {layer.evidence_type && (
                        <span className={`badge-evidence evidence-${layer.evidence_type}`}>
                          {layer.evidence_type.replace('_', ' ')}
                        </span>
                      )}
                      <span className={`badge-status ${isFailed ? 'fail' : 'pass'}`}>
                        {layer.hasData ? (layer.passed ? 'PASS' : 'TRIGGERED') : 'READY'}
                      </span>
                    </div>
                  </div>
                  
                  <div className="layer-telemetry-row">
                    <div className="score-container">
                      <span className="telemetry-label">Risk Weight:</span>
                      <div className="score-mini-bar">
                        <div
                          className={`score-mini-fill ${layer.score > 0.6 ? 'high' : layer.score > 0.3 ? 'med' : 'low'}`}
                          style={{ width: `${Math.max(3, layer.score * 100)}%` }}
                        />
                      </div>
                      <span className="score-val">{(layer.score * 100).toFixed(1)}%</span>
                    </div>

                    {layer.latency_ms != null && (
                      <span className="telemetry-latency">⏱ {layer.latency_ms.toFixed(2)} ms</span>
                    )}
                  </div>
                </div>
                <button className="expand-chevron">{expandedLayer === i ? '▲' : '▼'}</button>
              </div>

              {expandedLayer === i && layer.details && (
                <div className="vertical-layer-details">
                  <div className="details-heading">LAYER AUDIT DETAILS:</div>
                  <pre className="details-json">{JSON.stringify(layer.details, null, 2)}</pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
