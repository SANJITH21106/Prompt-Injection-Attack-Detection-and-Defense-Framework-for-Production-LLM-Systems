# Database Schema Documentation

## Overview

SQLite is used as the local persistence database. SQLAlchemy 2.x provides the ORM/database abstraction layer via `aiosqlite` for async operations.

**No PostgreSQL dependencies** — no asyncpg, psycopg2, or PostgreSQL-specific SQL.

## Database File

- Location: `backend/prompt_defense.db`
- Created automatically on backend startup
- Git-ignored (listed in `.gitignore`)
- Connection URL: `sqlite+aiosqlite:///./prompt_defense.db`

## Tables

### request_logs

Stores every chat request with its full security decision trace.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER (PK, auto) | Primary key |
| request_id | VARCHAR(64) | Unique request identifier (indexed) |
| timestamp | DATETIME | UTC timestamp |
| user_prompt | TEXT | Original user prompt |
| sanitized_prompt | TEXT (nullable) | Sanitized version if modified |
| security_decision | VARCHAR(16) | ALLOW / SANITIZE / BLOCK |
| risk_score | FLOAT | Combined risk score (0.0–1.0) |
| confidence | FLOAT | Decision confidence (0.0–1.0) |
| hard_block | BOOLEAN | Whether this was a hard security violation |
| decision_reason | TEXT (nullable) | Human-readable explanation |
| triggered_layers | JSON (nullable) | List of layer names that triggered |
| llm_response | TEXT (nullable) | Gemini response (null if blocked) |
| was_output_safe | BOOLEAN (nullable) | Output re-analysis result |
| total_latency_ms | FLOAT | End-to-end pipeline latency |

### security_events

Records each pipeline event for SSE streaming and audit trail.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER (PK, auto) | Primary key |
| request_id | VARCHAR(64) (FK) | Links to request_logs |
| timestamp | DATETIME | UTC timestamp |
| event_type | VARCHAR(64) | Event type (see below) |
| severity | VARCHAR(16) (nullable) | LOW / MEDIUM / HIGH / CRITICAL |
| layer_name | VARCHAR(64) (nullable) | Which layer generated this event |
| status | VARCHAR(32) (nullable) | PASS / FAIL / decision value |
| details | JSON (nullable) | Event-specific details |
| score | FLOAT (nullable) | Score if applicable |
| latency_ms | FLOAT (nullable) | Latency if applicable |

**Event Types:**
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

### layer_results

Individual detection results for each of the 6 firewall layers per request.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER (PK, auto) | Primary key |
| request_id | VARCHAR(64) (FK) | Links to request_logs |
| layer_name | VARCHAR(64) | Layer name |
| passed | BOOLEAN | Whether the layer passed |
| score | FLOAT | Risk score (0.0–1.0) |
| evidence_type | VARCHAR(32) (nullable) | deterministic / strong_semantic / weak_anomaly |
| hard_block_trigger | BOOLEAN (nullable) | Whether this layer triggered an immediate hard block |
| details | JSON (nullable) | Layer-specific analysis details |
| latency_ms | FLOAT | Layer execution time |
| timestamp | DATETIME | UTC timestamp |

## Relationships

```
RequestLog (1) ──→ (N) SecurityEvent
RequestLog (1) ──→ (N) LayerResult
```

A single request is traceable through all its security events and layer results.

## SQLite Compatibility

- Uses SQLAlchemy's portable `JSON` type (no JSONB)
- No ARRAY types — lists stored as JSON
- UUIDs stored as VARCHAR strings
- No PostgreSQL-specific functions
- All queries use SQLAlchemy ORM (no raw PostgreSQL SQL)
