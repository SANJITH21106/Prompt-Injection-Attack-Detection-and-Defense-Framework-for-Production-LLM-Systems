# Prompt Injection Attack Detection & Defense Framework for Production LLM Systems

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React 19](https://img.shields.io/badge/Frontend-React%2019-61DAFB.svg)](https://react.dev/)
[![SQLite](https://img.shields.io/badge/Database-SQLite%20(Async)-003B57.svg)](https://www.sqlite.org/)
[![OWASP LLM Top 10](https://img.shields.io/badge/Security-OWASP%20LLM01%20Compliant-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

An enterprise-grade, in-line security firewall and threat-intelligence runtime designed to protect Large Language Model (LLM) applications against prompt injection attacks, jailbreaks, data exfiltration, and malicious database manipulation.

---

## Executive Summary & Problem Statement

Modern Large Language Model applications suffer from a fundamental architectural vulnerability: **instructions and untrusted user inputs share the exact same contextual channel**. Attackers exploit this design flaw through:

- **Direct Prompt Injections & Jailbreaks**: Overriding developer system prompts via persona adoption, instruction hijacking, and linguistic disguise.
- **Indirect Injections**: Hiding malicious instructions inside benign contexts, articles, or retrieval-augmented generation (RAG) documents.
- **Tool Exploitation & Second-Order SQLi**: Tricking autonomous LLM agents into constructing destructive database statements (e.g., `DROP TABLE`, exfiltration queries).
- **Sensitive Data Exfiltration**: Prompting the model to regurgitate system secrets, credentials, or private training artifacts.

This framework introduces a **synchronous, multi-layered defensive firewall** that inspects, scores, and filters prompts before they ever reach the model, supplemented by post-generation egress filtering and live telemetry.

---

## Key Innovations

1. **Sub-10ms Multi-Layer Defense-in-Depth**: 6 independent inspection layers operating in parallel and sequential pipelines to minimize latency overhead while maximizing detection coverage.
2. **Two-Stage Decision Engine**:
   - **Stage A (Deterministic Hard-Stop)**: Instant zero-compromise termination for catastrophic signatures (e.g., destructive SQL AST manipulations, raw exfiltration directives).
   - **Stage B (Calibrated Multi-Signal Aggregation)**: Evidence-weighted risk aggregation dynamically discounting weak contextual anomalies to prevent false positives on legitimate technical inputs.
3. **AST-Based Semantic SQL Analysis**: Parses incoming prompt constructs with `sqlglot` to catch SQL injection attempts structurally rather than relying purely on naive keyword matching.
4. **Sliding-Window Spatial Chunk Anomaly Detection**: Uncovers sophisticated indirect injections hidden deeply within benign long-form text documents.
5. **Bidirectional Firewall**: Evaluates both ingress prompts and egress LLM generations to ensure model hallucinations or leaked credentials never reach the end user.
6. **Live Threat Monitoring SOC**: Server-Sent Events (SSE) stream event-driven telemetry into an operational dashboard for real-time security audits and forensic traces.

---

## Architectural Workflow

```
[ Inbound User Request ]
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│              6-Layer Ingress Security Firewall                  │
│                                                                 │
│  [L1] Pattern Check    ── Attack signatures & heuristic regex  │
│  [L2] SQL & Intent     ── AST semantic parsing via sqlglot      │
│  [L3] ML Safety        ── TF-IDF + Calibrated Logistic Model    │
│  [L4] Guardrails       ── Policy & instruction override checks  │
│  [L5] Chunk Anomaly    ── Sliding-window payload localization   │
│  [L6] Proxy Anomaly    ── Entropy, repetition & suffix analysis │
└─────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Security Decision Engine                     │
│                                                                 │
│  Stage A: Hard Violation Check ──> [ BLOCK ] (Immediate Stop)   │
│  Stage B: Weighted Evidence Matrix                              │
│           ├── Deterministic Weight (1.0x)                       │
│           ├── Strong Semantic Weight (1.0x)                     │
│           └── Weak Anomaly Weight (0.5x)                        │
└─────────────────────────────────────────────────────────────────┘
          │
          ├── [ BLOCK / SANITIZE ] ──> Security Event Log & Audit
          │
          ▼ [ ALLOW ]
┌───────────────────────────────────┐
│     Upstream Foundation Model     │  (Google Gemini API)
└───────────────────────────────────┘
          │
          ▼
┌───────────────────────────────────┐
│     Egress Output Re-Analyzer     │  (PII, Secret Redaction, Exfiltration)
└───────────────────────────────────┘
          │
          ▼
[ Verified Safe Response to Client ]
```

---

## 6-Layer Security Firewall Deep Dive

| Layer | Name | Methodology & Inspection Mechanism | Signal Classification |
|---|---|---|---|
| **L1** | **Deterministic Pattern Engine** | Regex compilation against 30+ curated prompt injection signatures, delimiter exploits, and bypass tokens. | `Deterministic` |
| **L2** | **SQL & Intent AST Analyzer** | Abstract Syntax Tree parsing through `sqlglot` targeting dialect statements, destructive operations (`DROP`, `DELETE`), and tautology exploits. | `Deterministic` |
| **L3** | **Machine Learning Classifier** | TF-IDF token vectorizer coupled with a calibrated Logistic Regression safety model trained on prompt injection corpora. | `Strong Semantic` |
| **L4** | **Instruction Guardrails** | Behavioral constraints identifying system role impersonation (`[SYSTEM]`, `ADMIN`), delimiter manipulation, and goal diversion. | `Strong Semantic` |
| **L5** | **Chunk Anomaly Analysis** | Sliding-window spatial concentration analyzer identifying localized malicious payloads embedded in voluminous benign text. | `Weak Anomaly` |
| **L6** | **Statistical Proxy Analyzer** | Multi-indicator statistical evaluation calculating Shannon entropy, character distribution anomalies, and adversarial suffixes. | `Weak Anomaly` |

### Two-Stage Decision Matrix

To prevent high-confidence false alarms from degrading user experience while guaranteeing strict safety:

```math
\text{Risk Score} = \sum_{i=1}^{6} (w_i \cdot s_i \cdot c_i)
```

- **Deterministic Findings**: Triggers Stage A hard block immediately, bypassing model invocation entirely.
- **Weak Anomalies**: Down-weighted by 50% ($c_i = 0.5$) to prevent benign edge cases (unusual punctuation, foreign characters) from incorrectly triggering a block without corroborating evidence.
- **Decision Thresholds**:
  - `Risk < 0.45`: **ALLOW**
  - `0.45 <= Risk < 0.75`: **SANITIZE** (Strip detected injection vectors and proceed safely)
  - `Risk >= 0.75` or `Hard Block`: **BLOCK** (Deny request and generate forensic alert)

---

## OWASP LLM Top 10 Coverage

| OWASP Threat Category | Framework Defense Mechanism |
|---|---|
| **LLM01: Prompt Injection** | Multi-layered L1, L3, L4, and L5 inspection intercepting direct and indirect injection vectors. |
| **LLM02: Sensitive Information Disclosure** | Egress Output Analyzer scanning for leaked credentials, API tokens, and secret leakage. |
| **LLM06: Excessive Agency / Insecure Output** | AST SQL parsing preventing downstream autonomous tool exploitation and destructive statements. |
| **LLM08: Vector and Embedding Weaknesses** | L5 Chunking identifying adversarial embeddings injected via RAG context retrieval. |

---

## Tech Stack & System Architecture

### Backend Core
- **Framework**: FastAPI (Asynchronous Python ASGI)
- **Database**: Async SQLite via SQLAlchemy 2.x ORM & `aiosqlite`
- **Machine Learning**: `scikit-learn` (TF-IDF vectorizer + calibrated classification)
- **SQL Analysis**: `sqlglot` Abstract Syntax Tree parser
- **LLM Integration**: Official Google Gemini SDK (`google-genai`)
- **Real-Time Streaming**: Server-Sent Events (SSE) via `sse-starlette`

### Frontend Application
- **Framework**: React 19 + Vite
- **Architecture**: Dual-portal architecture:
  - **Protected AI Interface**: Production-ready LLM interaction portal with security status indicators.
  - **Security Operations Center (SOC) Dashboard**: Live telemetry feed, latency analytics, and forensic trace viewer.

---

## System Setup & Execution

### Prerequisites
- Python 3.11 or higher
- Node.js 18 or higher
- Google Gemini API Key

### 1. Environment Configuration

Copy the sample environment file and configure your credentials:

```bash
cp .env.example .env
```

Edit `.env` to provide your configuration:
```env
DATABASE_URL=sqlite+aiosqlite:///./prompt_defense.db
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.0-flash
CORS_ORIGINS=http://localhost:5173
```

> **Security Note**: The `.env` file is strictly ignored by version control. API keys and database files are never committed or exposed to the frontend client.

---

### 2. Backend Initialization

1. Create and activate a virtual environment:
   ```bash
   # On macOS / Linux
   python3 -m venv venv
   source venv/bin/activate

   # On Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. Launch the FastAPI server:
   ```bash
   cd backend
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

---

### 3. Frontend Initialization

1. Install project dependencies:
   ```bash
   cd frontend
   npm install
   ```

2. Start the development server:
   ```bash
   npm run dev
   ```

3. Access the web interface through your preferred browser on the designated local development port configured in your environment.

---

## Automated Verification & Test Suite

The security pipeline includes automated regression and attack validation tests:

```bash
cd backend
python tests/test_security.py
```

### Test Validation Suite Covers:
- **Test 1**: Benign operational prompt (Verifies zero false positives).
- **Test 2**: Direct prompt injection with instruction overrides (Verifies multi-layer block).
- **Test 3**: SQL injection exploit with destructive statements (Verifies AST-level Stage A hard block).
- **Test 4**: Statistical anomaly isolation (Verifies weak anomalies do not cause false blocks).
- **Test 5**: Multi-signal compound adversary attack (Verifies cross-layer correlation).
- **Test 6**: Sanitization path execution (Verifies moderate-risk neutralization).

---

## API Reference Summary

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/chat` | `POST` | Core guarded LLM pipeline endpoint (runs firewall, model, and output analyzer). |
| `/api/security/stats` | `GET` | Aggregated threat statistics, blocked request ratios, and layer trigger distribution. |
| `/api/security/events` | `GET` | Historical security events with paginated audit logs. |
| `/api/security/requests/{id}/trace` | `GET` | Detailed layer-by-layer inspection trace and latency breakdown for forensic audit. |
| `/api/events/stream` | `GET` | Real-time Server-Sent Events (SSE) telemetry stream for SOC dashboards. |
| `/api/health` | `GET` | Microservice health check and upstream connectivity status. |

---

## Enterprise Security Architecture Principles

- **Zero Client Credential Exposure**: Client applications never receive direct access to LLM API keys. All calls are mediated through the secure firewall boundary.
- **Fail-Safe Defaults**: If any component within the critical security path encounters an unhandled exception, the default policy fails securely to prevent uninspected execution.
- **Data Minimization & Air-Gapped Readiness**: All firewall classifications (regex, AST, ML, statistical) execute locally on CPU with near-zero latency and no external telemetry transmission.
- **Cryptographic Auditability**: Every request is assigned a unique UUID trace identifier, linking incoming prompts, layer scores, decisions, and upstream tokens.

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
