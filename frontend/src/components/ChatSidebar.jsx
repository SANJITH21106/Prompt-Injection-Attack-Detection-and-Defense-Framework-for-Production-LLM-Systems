import React from 'react';

export default function ChatSidebar({
  sessions,
  activeSessionId,
  onSelectSession,
  onNewChat,
  onDeleteSession,
  isOpen,
  onToggle,
}) {
  return (
    <aside className={`chat-sidebar ${isOpen ? 'open' : 'closed'}`}>
      <div className="sidebar-header">
        <button className="new-chat-btn" onClick={onNewChat}>
          <span className="plus-icon">+</span>
          <span>New Chat</span>
        </button>
        <button
          className="sidebar-toggle-btn"
          onClick={onToggle}
          title={isOpen ? 'Collapse sidebar' : 'Open sidebar'}
        >
          {isOpen ? '◀' : '▶'}
        </button>
      </div>

      <div className="sidebar-session-list">
        <div className="session-group-title">Recent Conversations</div>
        {sessions.length === 0 ? (
          <div className="empty-history">No conversations yet</div>
        ) : (
          sessions.map((session) => {
            const isActive = session.id === activeSessionId;
            return (
              <div
                key={session.id}
                className={`session-item ${isActive ? 'active' : ''}`}
                onClick={() => onSelectSession(session.id)}
              >
                <div className="session-icon">💬</div>
                <div className="session-info">
                  <div className="session-title">{session.title || 'New Chat'}</div>
                  <div className="session-date">
                    {new Date(session.updatedAt).toLocaleDateString([], {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </div>
                </div>
                <button
                  className="delete-session-btn"
                  title="Delete chat"
                  onClick={(e) => onDeleteSession(session.id, e)}
                >
                  ✕
                </button>
              </div>
            );
          })
        )}
      </div>

      <div className="sidebar-footer">
        <div className="sidebar-badge">🛡️ Security Active</div>
      </div>
    </aside>
  );
}
