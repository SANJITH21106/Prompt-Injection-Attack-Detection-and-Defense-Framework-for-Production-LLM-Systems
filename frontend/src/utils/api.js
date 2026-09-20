/**
 * API client utilities — all requests go through the Vite proxy to FastAPI.
 * GEMINI_API_KEY is never exposed here.
 */

const API_BASE = '/api';

export async function sendChat(prompt) {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Chat API error: ${res.status} — ${err}`);
  }
  return res.json();
}

export async function getSecurityEvents(limit = 50, offset = 0) {
  const res = await fetch(`${API_BASE}/security/events?limit=${limit}&offset=${offset}`);
  return res.json();
}

export async function getRequests(limit = 50, offset = 0, decision = '') {
  let url = `${API_BASE}/security/requests?limit=${limit}&offset=${offset}`;
  if (decision) url += `&decision=${decision}`;
  const res = await fetch(url);
  return res.json();
}

export async function getRequestTrace(requestId) {
  const res = await fetch(`${API_BASE}/security/requests/${requestId}/trace`);
  return res.json();
}

export async function getSecurityStats() {
  const res = await fetch(`${API_BASE}/security/stats`);
  return res.json();
}

export async function healthCheck() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}
