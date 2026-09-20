import { useState, useEffect, useCallback, useRef } from 'react';
import { sendChat } from '../utils/api';
import {
  loadSessions,
  saveSessions,
  getActiveSessionId,
  setActiveSessionId,
  createNewSessionObject,
} from '../utils/chatStorage';

export function useChat() {
  const [sessions, setSessions] = useState(() => {
    const saved = loadSessions();
    if (saved.length > 0) return saved;
    const initial = createNewSessionObject();
    return [initial];
  });

  const [activeSessionId, setActiveId] = useState(() => {
    const savedId = getActiveSessionId();
    const existing = loadSessions();
    if (savedId && existing.some(s => s.id === savedId)) {
      return savedId;
    }
    return existing.length > 0 ? existing[0].id : null;
  });

  const [loading, setLoading] = useState(false);

  // Sync activeSessionId to localStorage
  useEffect(() => {
    if (activeSessionId) {
      setActiveSessionId(activeSessionId);
    }
  }, [activeSessionId]);

  // Sync sessions to localStorage
  useEffect(() => {
    saveSessions(sessions);
  }, [sessions]);

  // Ensure an active session always exists
  useEffect(() => {
    if (!activeSessionId && sessions.length > 0) {
      setActiveId(sessions[0].id);
    }
  }, [activeSessionId, sessions]);

  const activeSession = sessions.find(s => s.id === activeSessionId) || sessions[0] || null;
  const messages = activeSession ? activeSession.messages : [];

  const updateActiveSessionMessages = useCallback((updater) => {
    setSessions(prevSessions => {
      return prevSessions.map(s => {
        if (s.id === (activeSessionId || prevSessions[0]?.id)) {
          const newMessages = typeof updater === 'function' ? updater(s.messages) : updater;
          // Auto-generate title from first user prompt if still default
          let title = s.title;
          if (title === 'New Chat') {
            const firstUser = newMessages.find(m => m.role === 'user');
            if (firstUser) {
              title = firstUser.content.length > 28
                ? firstUser.content.substring(0, 28) + '...'
                : firstUser.content;
            }
          }
          return {
            ...s,
            title,
            updatedAt: Date.now(),
            messages: newMessages,
          };
        }
        return s;
      });
    });
  }, [activeSessionId]);

  const newChat = useCallback(() => {
    const fresh = createNewSessionObject();
    setSessions(prev => [fresh, ...prev]);
    setActiveId(fresh.id);
  }, []);

  const selectSession = useCallback((id) => {
    setActiveId(id);
  }, []);

  const deleteSession = useCallback((id, e) => {
    e?.stopPropagation();
    setSessions(prev => {
      const remaining = prev.filter(s => s.id !== id);
      if (remaining.length === 0) {
        const fresh = createNewSessionObject();
        setActiveId(fresh.id);
        return [fresh];
      }
      if (activeSessionId === id) {
        setActiveId(remaining[0].id);
      }
      return remaining;
    });
  }, [activeSessionId]);

  const send = useCallback(async (prompt) => {
    if (!prompt.trim() || loading) return;

    const userMsg = { role: 'user', content: prompt, timestamp: Date.now() };
    updateActiveSessionMessages(prev => [...prev, userMsg]);
    setLoading(true);

    try {
      const result = await sendChat(prompt);

      if (result.security_decision.decision === 'BLOCK') {
        const blockMsg = {
          role: 'blocked',
          content: `🛡️ Request blocked: ${result.security_decision.reason}`,
          security: result.security_decision,
          layers: result.layer_results,
          request_id: result.request_id,
          timestamp: Date.now(),
        };
        updateActiveSessionMessages(prev => [...prev, blockMsg]);
      } else {
        const aiMsg = {
          role: 'assistant',
          content: result.response || 'No response received.',
          security: result.security_decision,
          layers: result.layer_results,
          request_id: result.request_id,
          timestamp: Date.now(),
        };
        updateActiveSessionMessages(prev => [...prev, aiMsg]);
      }
    } catch (err) {
      const errMsg = {
        role: 'blocked',
        content: `Error: ${err.message}`,
        timestamp: Date.now(),
      };
      updateActiveSessionMessages(prev => [...prev, errMsg]);
    } finally {
      setLoading(false);
    }
  }, [loading, updateActiveSessionMessages]);

  const clearMessages = useCallback(() => {
    updateActiveSessionMessages([]);
  }, [updateActiveSessionMessages]);

  const regenerate = useCallback(async () => {
    if (loading) return;
    const currentMsgs = messages;
    if (currentMsgs.length === 0) return;

    // Find the last user message
    let lastUserIndex = -1;
    for (let i = currentMsgs.length - 1; i >= 0; i--) {
      if (currentMsgs[i].role === 'user') {
        lastUserIndex = i;
        break;
      }
    }
    if (lastUserIndex === -1) return;

    const lastPrompt = currentMsgs[lastUserIndex].content;
    const trimmed = currentMsgs.slice(0, lastUserIndex + 1);
    updateActiveSessionMessages(trimmed);
    setLoading(true);

    try {
      const result = await sendChat(lastPrompt);
      if (result.security_decision.decision === 'BLOCK') {
        const blockMsg = {
          role: 'blocked',
          content: `🛡️ Request blocked: ${result.security_decision.reason}`,
          security: result.security_decision,
          layers: result.layer_results,
          request_id: result.request_id,
          timestamp: Date.now(),
        };
        updateActiveSessionMessages(prev => [...prev, blockMsg]);
      } else {
        const aiMsg = {
          role: 'assistant',
          content: result.response || 'No response received.',
          security: result.security_decision,
          layers: result.layer_results,
          request_id: result.request_id,
          timestamp: Date.now(),
        };
        updateActiveSessionMessages(prev => [...prev, aiMsg]);
      }
    } catch (err) {
      const errMsg = {
        role: 'blocked',
        content: `Error: ${err.message}`,
        timestamp: Date.now(),
      };
      updateActiveSessionMessages(prev => [...prev, errMsg]);
    } finally {
      setLoading(false);
    }
  }, [loading, messages, updateActiveSessionMessages]);

  return {
    sessions,
    activeSessionId,
    messages,
    loading,
    send,
    regenerate,
    newChat,
    selectSession,
    deleteSession,
    clearMessages,
  };
}
