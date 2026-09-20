# API Documentation

## Base URL
Default: `http://localhost:8000`

Interactive OpenAPI Docs: `http://localhost:8000/docs`

---

## 1. Health Endpoint

### `GET /api/health`
Returns service status and active configuration.

**Response `200 OK`:**
```json
{
  "status": "healthy",
  "gemini_model": "gemini-2.0-flash",
  "database": "sqlite+aiosqlite:"
}
```

---

## 2. Chat & Firewall Endpoint

### `POST /api/chat`
Submits a user prompt to the security pipeline and optionally returns LLM output.

**Request Body:**
```json
{
  "prompt": "What is machine learning?",
  "conversation_id": "optional-session-id"
}
```

**Response `200 OK` (Example ALLOW):**
```json
{
  "request_id": "1dcd1fd5-b9ce-4e",
  "response": "Machine learning is a field of artificial intelligence...",
  "security_decision": {
    "decision": "ALLOW",
    "risk_score": 0.0636,
    "confidence": 0.5,
    "reason": "All security layers passed. Combined risk score: 0.06.",
    "hard_block": false,
    "triggered_layers": []
  },
  "layer_results": [
    {
      "layer_name": "Rule-Based Detection",
      "passed": true,
      "score": 0.0,
      "details": { "reason": "No known attack patterns detected." },
      "latency_ms": 0.42,
      "evidence_type": "weak_anomaly",
      "hard_block_trigger": false
    },
    ...
  ],
  "total_latency_ms": 124.5,
  "was_output_safe": true
}
```

**Response `200 OK` (Example BLOCK):**
```json
{
  "request_id": "73f7597c-1309-45",
  "response": null,
  "security_decision": {
    "decision": "BLOCK",
    "risk_score": 0.9181,
    "confidence": 0.98,
    "reason": "Hard security violation: Stacked destructive SQL queries",
    "hard_block": true,
    "triggered_layers": ["SQL & Intent Analysis"]
  },
  "layer_results": [...],
  "total_latency_ms": 2.8,
  "was_output_safe": null
}
```

---

## 3. Real-Time Events (SSE)

### `GET /api/events/stream`
Server-Sent Events endpoint pushing real-time pipeline events.

**Content-Type:** `text/event-stream`

**Emitted Events:**
- `REQUEST_RECEIVED`
- `LAYER_STARTED`
- `LAYER_COMPLETED`
- `SECURITY_DECISION`
- `GEMINI_REQUEST_STARTED`
- `GEMINI_RESPONSE_RECEIVED`
- `OUTPUT_ANALYSIS_STARTED`
- `OUTPUT_ANALYSIS_COMPLETED`
- `REQUEST_COMPLETED`
- `REQUEST_BLOCKED`

---

## 4. Security Dashboard Endpoints

### `GET /api/security/requests`
Returns paginated historical request logs from SQLite.
- Query parameters:
  - `limit` (int, default 50)
  - `offset` (int, default 0)
  - `decision` (optional string filter: `ALLOW`, `SANITIZE`, `BLOCK`)

### `GET /api/security/requests/{request_id}/trace`
Returns the complete audit trace for a request, including all 6 layer results and all pipeline events.

### `GET /api/security/events`
Returns paginated security event log from SQLite.

### `GET /api/security/stats`
Returns aggregated security statistics:
- `total_requests`
- `allowed_requests`
- `sanitized_requests`
- `blocked_requests`
- `hard_blocks`
- `avg_latency_ms`
- `avg_risk_score`
- `layer_trigger_counts`
- `attack_type_counts`
