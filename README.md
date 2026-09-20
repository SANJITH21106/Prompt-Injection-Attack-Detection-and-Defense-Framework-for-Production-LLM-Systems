# Real-Time Defense Against Prompt Injection Attacks

A runtime security framework that protects LLM applications from prompt injection attacks, data exfiltration, SQL injection, and unsafe model outputs. Features two web interfaces: a **ChatGPT-like Chat UI** and a **Security Monitoring Dashboard**, both communicating with a FastAPI backend.

## Architecture

```
User → React Chat UI → FastAPI → 6-Layer Security Firewall → Security Decision Engine → Gemini API → Output Re-Analysis → Response
                                                                                                                              ↓
                                                                                            Security Events → SSE → Dashboard
                                                                                                                    ↓
                                                                                                               SQLAlchemy → SQLite
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI (Python) |
| LLM | Google Gemini API via `google-genai` SDK |
| Database | SQLite via SQLAlchemy 2.x + aiosqlite |
| Frontend | React + Vite |
| Real-time | Server-Sent Events (SSE) via sse-starlette |
| ML | scikit-learn (TF-IDF + LogisticRegression) |
| SQL Analysis | sqlglot |

## Security Firewall — 6 Layers

| Layer | Name | Evidence Type |
|-------|------|---------------|
| L1 | Rule-Based Pattern Check | Regex attack signatures (30+ patterns) |
| L2 | SQL & Intent Analysis | sqlglot parsing + injection detection |
| L3 | ML Safety Classifier | TF-IDF + Logistic Regression (trained on boot) |
| L4 | Prompt-Injection Guardrails | Security policy enforcement |
| L5 | Chunk Anomaly Analysis | Detects hidden malicious content in benign context |
| L6 | Perplexity / Statistical Anomaly Analysis | Statistical proxy indicators (see below) |

### Security Decision Engine

The decision engine replaces a simple `max(score)` approach with a two-stage process:

**Stage A — Hard Security Violations**: Certain deterministic findings (e.g., `DROP TABLE`, confirmed injection structure) trigger an **immediate BLOCK** regardless of other layer scores.

**Stage B — Multi-Signal Risk Aggregation**: For non-critical cases, evidence from all 6 layers is combined using **configurable weights**:

```
RULE_WEIGHT=0.25    SQL_WEIGHT=0.20    ML_WEIGHT=0.25
GUARDRAIL_WEIGHT=0.20    CHUNK_WEIGHT=0.05    ANOMALY_WEIGHT=0.05
```

Evidence is classified into three types:
- **Deterministic**: Confirmed attack → full weight
- **Strong Semantic**: High-confidence signal → full weight
- **Weak Anomaly**: Statistical/contextual → discounted (×0.5 weight)

This prevents false positives from weak anomaly signals (e.g., unusual punctuation, long text) independently causing a BLOCK.

### Layer 6 — Perplexity / Statistical Anomaly Analysis

This layer uses **statistical proxy indicators**, NOT true language-model perplexity. True token-level perplexity requires a language model to compute log-likelihoods, which is not available in the current lightweight implementation.

Statistical indicators used:
- Repetitive sequence detection
- Encoding/obfuscation analysis
- Abnormal character distribution (entropy)
- Token/word distribution analysis
- Adversarial suffix pattern detection
- Special character ratio analysis

The dashboard clearly indicates when results are a statistical proxy (`analysis_type: "statistical_proxy"`).

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+
- Google Gemini API key from [AI Studio](https://aistudio.google.com/)

### Backend

```bash
cd backend
python -m venv venv
# Windows: venv\Scripts\activate | macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
```

Create `backend/.env`:
```env
DATABASE_URL=sqlite+aiosqlite:///./prompt_defense.db
GEMINI_API_KEY=your_api_key_here
GEMINI_MODEL=gemini-2.0-flash
```

Start the server:
```bash
cd backend
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### Run Tests

```bash
cd backend
python tests/test_security.py
```

## Database

SQLite is the primary and only database. SQLAlchemy provides the ORM/database abstraction layer.

- **Engine**: SQLAlchemy 2.x async + aiosqlite
- **File**: `backend/prompt_defense.db` (auto-created on startup, git-ignored)
- **Models**: RequestLog, SecurityEvent, LayerResult
- **No PostgreSQL dependencies** — no asyncpg, psycopg2, or PostgreSQL-specific SQL

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/chat` | Send prompt through security pipeline |
| GET | `/api/security/events` | Paginated security event history |
| GET | `/api/security/events/{id}` | Single event detail |
| GET | `/api/security/requests` | Request history |
| GET | `/api/security/requests/{id}/trace` | Full request trace with layers |
| GET | `/api/security/stats` | Aggregate statistics from SQLite |
| GET | `/api/events/stream` | SSE real-time event stream |
| GET | `/api/health` | Health check |

## Environment Configuration

All security parameters are configurable via `.env`:

```env
# Database
DATABASE_URL=sqlite+aiosqlite:///./prompt_defense.db

# Gemini (never hard-coded, never exposed to frontend)
GEMINI_API_KEY=your_key
GEMINI_MODEL=gemini-2.0-flash

# Decision Engine Weights
RULE_WEIGHT=0.25
SQL_WEIGHT=0.20
ML_WEIGHT=0.25
GUARDRAIL_WEIGHT=0.20
CHUNK_WEIGHT=0.05
ANOMALY_WEIGHT=0.05

# Decision Thresholds
SANITIZE_THRESHOLD=0.45
BLOCK_THRESHOLD=0.75
```
