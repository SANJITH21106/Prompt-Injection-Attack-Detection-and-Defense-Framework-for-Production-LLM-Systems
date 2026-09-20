/**
 * LocalStorage persistence for ChatGPT-like multi-session chat history.
 */

const STORAGE_KEY = 'prompt_defense_chat_sessions';
const ACTIVE_KEY = 'prompt_defense_active_session_id';

export function loadSessions() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to load chat sessions:', e);
    return [];
  }
}

export function saveSessions(sessions) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(sessions));
  } catch (e) {
    console.error('Failed to save chat sessions:', e);
  }
}

export function getActiveSessionId() {
  return localStorage.getItem(ACTIVE_KEY) || null;
}

export function setActiveSessionId(id) {
  if (id) {
    localStorage.setItem(ACTIVE_KEY, id);
  } else {
    localStorage.removeItem(ACTIVE_KEY);
  }
}

export function createNewSessionObject(initialPrompt = '') {
  const id = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
  const title = initialPrompt
    ? (initialPrompt.length > 30 ? initialPrompt.substring(0, 30) + '...' : initialPrompt)
    : 'New Chat';
  return {
    id,
    title,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    messages: [],
  };
}
