import { useState, useEffect, useCallback } from 'react';
import ChatPage from './pages/ChatPage';
import DashboardPage from './pages/DashboardPage';
import { useSSE } from './hooks/useSSE';
import { healthCheck } from './utils/api';

/**
 * Root App — Unified AI Security Operations Console.
 * Real-time SSE stream, backend health monitoring, multi-theme support (Dark/Light).
 */
export default function App() {
  const [page, setPage] = useState('chat');
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('prompt_defense_theme') || 'dark';
  });

  const [systemHealth, setSystemHealth] = useState(null);
  const [selectedTraceId, setSelectedTraceId] = useState(null);

  // Real-time SSE event stream hook
  const { events, connected, clearEvents } = useSSE();

  // Apply theme to document root
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('prompt_defense_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Poll health endpoint periodically
  const checkHealth = useCallback(async () => {
    try {
      const data = await healthCheck();
      setSystemHealth(data);
    } catch {
      setSystemHealth({ status: 'unreachable' });
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const timer = setInterval(checkHealth, 30000);
    return () => clearInterval(timer);
  }, [checkHealth]);

  // Navigate to dashboard and inspect a specific trace
  const handleInspectTrace = (traceId) => {
    setSelectedTraceId(traceId);
    setPage('dashboard');
  };

  // Count threat blocks from live events
  const threatCount = events.filter(
    (e) => e.event_type === 'REQUEST_BLOCKED' || (e.decision && e.decision !== 'ALLOW')
  ).length;

  return (
    <div className="app-container">
      {/* Redesigned Security Console Header */}
      <header className="app-header">
        <div className="header-brand">
          <div className="brand-shield-wrapper">
            <span className="brand-shield-icon">🛡️</span>
            <span className="brand-pulse-beacon" />
          </div>
          <div className="brand-text-block">
            <div className="brand-title">
              <span className="title-highlight">PROMPT</span> DEFENSE
              <span className="brand-version-tag">GATEWAY v2.4</span>
            </div>
            <div className="brand-subtitle">
              Multi-Layer LLM Firewall & Real-Time Threat Interception
            </div>
          </div>
        </div>

        <div className="header-status-group">
          {/* Health Status Indicator */}
          <div
            className={`system-status-pill ${systemHealth?.status === 'healthy' ? 'pill-healthy' : 'pill-offline'}`}
            title={`Backend Status: ${systemHealth?.status || 'checking...'} | LLM: ${systemHealth?.gemini_model || 'standby'}`}
          >
            <span className="status-ping-dot" />
            <span className="status-pill-text">
              {systemHealth?.status === 'healthy'
                ? `GATEWAY ACTIVE · ${systemHealth.gemini_model?.replace('gemini-', '') || 'ONLINE'}`
                : 'CHECKING STATUS...'}
            </span>
          </div>

          {/* SSE Connection Status */}
          <div
            className={`stream-status-pill ${connected ? 'stream-connected' : 'stream-disconnected'}`}
            title="Real-time Server-Sent Events stream"
          >
            <span className={`pulse-circle ${connected ? 'pulse-green' : 'pulse-amber'}`} />
            <span className="stream-label">{connected ? 'STREAM LIVE' : 'CONNECTING'}</span>
          </div>
        </div>

        <nav className="header-nav">
          <button
            className={`nav-tab-btn ${page === 'chat' ? 'active' : ''}`}
            onClick={() => setPage('chat')}
            id="nav-chat-tab"
          >
            <span className="tab-icon">💬</span>
            <span className="tab-label">Defense Chat</span>
          </button>

          <button
            className={`nav-tab-btn ${page === 'dashboard' ? 'active' : ''}`}
            onClick={() => setPage('dashboard')}
            id="nav-dashboard-tab"
          >
            <span className="tab-icon">📊</span>
            <span className="tab-label">Security Dashboard</span>
            {threatCount > 0 && (
              <span className="tab-threat-badge" title={`${threatCount} threats recorded in live stream`}>
                {threatCount}
              </span>
            )}
          </button>

          <button
            className="theme-toggle-btn"
            onClick={toggleTheme}
            id="theme-toggle"
            title={theme === 'dark' ? 'Switch to Cyber Light Mode' : 'Switch to Dark Cyber Mode'}
          >
            <span className="theme-toggle-icon">{theme === 'dark' ? '☀️' : '🌙'}</span>
            <span className="theme-toggle-text">{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>
        </nav>
      </header>

      {/* Main App Body */}
      <main className="app-main">
        <div style={{ display: page === 'chat' ? 'contents' : 'none' }}>
          <ChatPage onInspectTrace={handleInspectTrace} />
        </div>
        <div style={{ display: page === 'dashboard' ? 'contents' : 'none' }}>
          <DashboardPage
            sseEvents={events}
            sseConnected={connected}
            onClearEvents={clearEvents}
            externalSelectedTraceId={selectedTraceId}
            onClearExternalTrace={() => setSelectedTraceId(null)}
          />
        </div>
      </main>
    </div>
  );
}
