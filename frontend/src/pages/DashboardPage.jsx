import { useState, useEffect, useCallback, useMemo } from 'react';
import { useSSE } from '../hooks/useSSE';
import { getSecurityStats, getRequests, getRequestTrace } from '../utils/api';
import TelemetryCard from '../components/TelemetryCard';
import LiveEventConsole from '../components/LiveEventConsole';
import RequestTrace from '../components/RequestTrace';

/**
 * Security Operations Center (SOC) Dashboard:
 *  - Real-time telemetry cards (actual stats from SQLite)
 *  - Firewall layer interception breakdown
 *  - Forensic Request Trace inspector
 *  - Live Event Console stream (SSE)
 *  - Filterable Request History table
 */
export default function DashboardPage({
  sseEvents = null,
  sseConnected = null,
  onClearEvents = null,
  externalSelectedTraceId = null,
  onClearExternalTrace = null,
}) {
  // Use props if provided from App.jsx, otherwise fallback to local hook
  const localSSE = useSSE();
  const events = sseEvents || localSSE.events;
  const connected = sseConnected !== null ? sseConnected : localSSE.connected;
  const clearEvents = onClearEvents || localSSE.clearEvents;

  const [stats, setStats] = useState(null);
  const [requests, setRequests] = useState([]);
  const [selectedTrace, setSelectedTrace] = useState(null);
  const [decisionFilter, setDecisionFilter] = useState(''); // '' | 'ALLOW' | 'BLOCK' | 'SANITIZE'
  const [loadingRequests, setLoadingRequests] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Fetch stats and request history
  const fetchData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [statsData, reqData] = await Promise.all([
        getSecurityStats(),
        getRequests(50, 0, decisionFilter),
      ]);
      setStats(statsData);
      setRequests(reqData);
    } catch {
      // Backend may be starting up
    } finally {
      setIsRefreshing(false);
    }
  }, [decisionFilter]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Load a specific request trace
  const loadTrace = useCallback(async (requestId) => {
    try {
      const trace = await getRequestTrace(requestId);
      setSelectedTrace(trace);
    } catch (err) {
      console.error('Failed to load trace:', err);
    }
  }, []);

  // Watch for external trace selection from ChatPage
  useEffect(() => {
    if (externalSelectedTraceId) {
      loadTrace(externalSelectedTraceId);
      onClearExternalTrace?.();
    }
  }, [externalSelectedTraceId, loadTrace, onClearExternalTrace]);

  // Auto-refresh when new REQUEST_COMPLETED or REQUEST_BLOCKED arrives
  useEffect(() => {
    const lastEvent = events[0];
    if (lastEvent && (lastEvent.event_type === 'REQUEST_COMPLETED' || lastEvent.event_type === 'REQUEST_BLOCKED')) {
      fetchData();
    }
  }, [events, fetchData]);

  // Layer trigger distribution computed from stats
  const layerTriggers = useMemo(() => {
    if (!stats?.layer_trigger_counts) return [];
    return Object.entries(stats.layer_trigger_counts).map(([name, count]) => ({
      name,
      count,
    })).sort((a, b) => b.count - a.count);
  }, [stats]);

  return (
    <div className="dashboard-page">
      {/* SOC Header Strip */}
      <div className="soc-header-strip">
        <div className="soc-header-left">
          <div className="soc-title-row">
            <span className="soc-shield-badge">🛡️</span>
            <span className="soc-title">SECURITY OPERATIONS CENTER</span>
            <span className="soc-tag">LIVE TELEMETRY</span>
          </div>
          <p className="soc-subtitle">
            Autonomous threat detection & 6-layer defense telemetry against adversarial prompt injection
          </p>
        </div>

        <div className="soc-header-right">
          <button
            className={`soc-refresh-btn ${isRefreshing ? 'spinning' : ''}`}
            onClick={fetchData}
            title="Refresh database statistics"
            disabled={isRefreshing}
          >
            <span>🔄</span>
            <span>{isRefreshing ? 'Refreshing...' : 'Refresh Stats'}</span>
          </button>
        </div>
      </div>

      {/* Primary Telemetry KPIs */}
      {stats ? (
        <div className="soc-telemetry-grid">
          <TelemetryCard
            title="TOTAL INGRESS REQUESTS"
            value={stats.total_requests}
            subtitle="Ingress prompts audited"
            status="info"
            icon="📊"
          />
          <TelemetryCard
            title="ATTACKS INTERCEPTED"
            value={stats.blocked_requests}
            badge={`${stats.total_requests > 0 ? ((stats.blocked_requests / stats.total_requests) * 100).toFixed(1) : 0}% Block Rate`}
            subtitle="Adversarial payloads neutralized"
            status="danger"
            icon="🛡️"
          />
          <TelemetryCard
            title="VERIFIED CLEAN REQUESTS"
            value={stats.allowed_requests}
            subtitle="Forwarded to LLM safely"
            status="safe"
            icon="✓"
          />
          <TelemetryCard
            title="HARD RULE BLOCKS"
            value={stats.hard_blocks}
            subtitle="Zero-tolerance instant tripwires"
            status={stats.hard_blocks > 0 ? 'danger' : 'safe'}
            icon="🚨"
          />
          <TelemetryCard
            title="AVG DEFENSE LATENCY"
            value={`${stats.avg_latency_ms.toFixed(0)} ms`}
            subtitle="Multi-layer pipeline overhead"
            status="purple"
            icon="⏱"
          />
          <TelemetryCard
            title="AVERAGE THREAT RISK"
            value={`${(stats.avg_risk_score * 100).toFixed(1)}%`}
            subtitle="Weighted risk posture"
            status={stats.avg_risk_score > 0.5 ? 'danger' : 'info'}
            icon="🎯"
          />
        </div>
      ) : (
        <div className="soc-telemetry-grid skeleton-grid">
          {[1, 2, 3, 4, 5, 6].map((k) => (
            <div key={k} className="telemetry-card skeleton-card">
              <div className="skeleton-line" style={{ width: '50%' }} />
              <div className="skeleton-line" style={{ width: '80%', height: 28, margin: '12px 0' }} />
              <div className="skeleton-line" style={{ width: '40%' }} />
            </div>
          ))}
        </div>
      )}

      {/* Trace Modal / Selected Trace Drawer */}
      {selectedTrace && (
        <div className="selected-trace-section">
          <RequestTrace trace={selectedTrace} onClose={() => setSelectedTrace(null)} />
        </div>
      )}

      {/* Layer Trigger Distribution Matrix */}
      {layerTriggers.length > 0 && (
        <div className="soc-layer-distribution-card">
          <div className="card-header-bar">
            <span className="card-header-title">🔥 THREAT INTERCEPTION BY DEFENSE LAYER</span>
            <span className="card-header-note">Accumulated triggers across all historical requests</span>
          </div>
          <div className="triggers-distribution-grid">
            {layerTriggers.map((item, idx) => {
              const maxCount = Math.max(...layerTriggers.map((t) => t.count), 1);
              const pct = (item.count / maxCount) * 100;
              return (
                <div key={idx} className="layer-trigger-bar-item">
                  <div className="trigger-bar-labels">
                    <span className="trigger-bar-name">{item.name}</span>
                    <span className="trigger-bar-count">{item.count} Triggers</span>
                  </div>
                  <div className="trigger-bar-track">
                    <div className="trigger-bar-fill" style={{ width: `${Math.max(4, pct)}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Main Split: Live Event Console & Filterable Request History */}
      <div className="soc-main-columns">
        {/* Left / Top: Live SSE Event Console */}
        <div className="soc-column-console">
          <LiveEventConsole
            events={events}
            connected={connected}
            onClear={clearEvents}
          />
        </div>

        {/* Right / Bottom: Request History Log */}
        <div className="soc-column-history">
          <div className="history-table-card">
            <div className="history-header">
              <div className="history-title-group">
                <span className="history-icon">📋</span>
                <span className="history-title">FORENSIC REQUEST AUDIT LOG</span>
                <span className="history-count-tag">{requests.length} Requests</span>
              </div>

              {/* Filter Tabs */}
              <div className="history-filters">
                {[
                  { label: 'All', value: '' },
                  { label: 'Allowed', value: 'ALLOW' },
                  { label: 'Blocked', value: 'BLOCK' },
                  { label: 'Sanitized', value: 'SANITIZE' },
                ].map((flt) => (
                  <button
                    key={flt.value}
                    className={`history-filter-btn ${decisionFilter === flt.value ? 'active' : ''}`}
                    onClick={() => setDecisionFilter(flt.value)}
                  >
                    {flt.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="history-table-wrapper">
              {requests.length === 0 ? (
                <div className="history-empty">
                  {loadingRequests ? 'Loading audit records...' : 'No matching audit records found.'}
                </div>
              ) : (
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>REQUEST ID</th>
                      <th>PROMPT INGRESS</th>
                      <th>DECISION</th>
                      <th>RISK</th>
                      <th>LATENCY</th>
                      <th>ACTION</th>
                    </tr>
                  </thead>
                  <tbody>
                    {requests.map((req, idx) => {
                      const dec = req.security_decision || 'ALLOW';
                      const isSelected = selectedTrace?.request_id === req.request_id;
                      return (
                        <tr
                          key={req.request_id || idx}
                          className={`history-row ${isSelected ? 'row-selected' : ''}`}
                        >
                          <td className="cell-id">
                            <code>{req.request_id ? req.request_id.slice(0, 8) : 'N/A'}</code>
                          </td>
                          <td className="cell-prompt" title={req.user_prompt}>
                            {req.user_prompt}
                          </td>
                          <td className="cell-decision">
                            <span className={`table-decision-badge badge-${dec.toLowerCase()}`}>
                              {dec === 'ALLOW' && '✓ '}
                              {dec === 'BLOCK' && '✕ '}
                              {dec === 'SANITIZE' && '⚠ '}
                              {dec}
                            </span>
                            {req.hard_block && (
                              <span className="table-hard-block-tag">HARD</span>
                            )}
                          </td>
                          <td className="cell-risk">
                            <span
                              className={`risk-text ${
                                req.risk_score >= 0.75
                                  ? 'text-danger'
                                  : req.risk_score >= 0.45
                                  ? 'text-warn'
                                  : 'text-safe'
                              }`}
                            >
                              {(req.risk_score * 100).toFixed(0)}%
                            </span>
                          </td>
                          <td className="cell-latency">
                            {req.total_latency_ms != null ? `${req.total_latency_ms.toFixed(0)}ms` : '-'}
                          </td>
                          <td className="cell-action">
                            <button
                              className="inspect-trace-btn"
                              onClick={() => loadTrace(req.request_id)}
                              title="Perform deep forensic trace"
                            >
                              🔬 Inspect
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
