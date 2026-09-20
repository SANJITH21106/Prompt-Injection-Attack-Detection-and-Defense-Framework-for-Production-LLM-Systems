# System Architecture

## Overview

Real-Time Prompt Defense is a high-performance, modular runtime security framework designed to protect Large Language Model (LLM) applications against prompt injection attacks, malicious SQL, sensitive data exfiltration, and model manipulation.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Client Layer                                  │
│   ┌───────────────────────────┐         ┌───────────────────────────┐   │
│   │    User Chat Interface    │         │    Security Dashboard     │   │
│   │  (Clean conversational)   │         │ (Live trace, metrics, SSE)│   │
│   └─────────────┬─────────────┘         └─────────────▲─────────────┘   │
└─────────────────┼─────────────────────────────────────┼─────────────────┘
                  │ POST /api/chat                      │ GET /api/events/stream
                  ▼                                     │ (SSE Real-Time Push)
┌───────────────────────────────────────────────────────┴─────────────────┐
│                           FastAPI Backend                               │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │                     Request Pipeline                            │   │
│   │                                                                 │   │
│   │   1. REQUEST_RECEIVED                                           │   │
│   │   2. 6-Layer Firewall Engine                                    │   │
│   │      ├── L1: Rule-Based Pattern Check (Regex signatures)        │   │
│   │      ├── L2: SQL & Intent Check (sqlglot AST + heuristics)      │   │
│   │      ├── L3: ML Safety Classifier (TF-IDF + SGDClassifier)      │   │
│   │      ├── L4: Prompt-Injection Guardrails (Policy enforcement)   │   │
│   │      ├── L5: Chunk Anomaly Analysis (Windowed density)          │   │
│   │      └── L6: Statistical Proxy Anomaly (Entropy & char metrics) │   │
│   │   3. Security Decision Engine                                   │   │
│   │      ├── Stage A: Hard-block check (deterministic violations)   │   │
│   │      └── Stage B: Weighted multi-signal risk aggregation        │   │
│   │   4. LLM Provider Execution (Google Gemini API via google-genai) │   │
│   │      └── ONLY executed if decision is ALLOW or SANITIZE         │   │
│   │   5. Output Re-Analysis (Sensitive data & leak detector)        │   │
│   │   6. Event Persistence & Real-time SSE Broadcast                │   │
│   └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ┌───────────────────────┐             ┌───────────────────────────┐   │
│   │  SQLite / SQLAlchemy  │             │     Async Event Bus       │   │
│   │   (aiosqlite async)   │             │   (Fan-out SSE queues)    │   │
│   └───────────────────────┘             └───────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Architectural Principles

1. **Defense-in-Depth (6 Independent Firewall Layers):**
   No single heuristic or classifier determines security alone. Each layer inspects different threat facets (lexical, syntactic, semantic, statistical, policy, and spatial/structural).

2. **Deterministic Hard-Blocks vs. Probabilistic Multi-Signal Aggregation:**
   - Destructive SQL payloads (`DROP TABLE`, `DELETE FROM`) and high-severity multiple guardrail breaches trigger immediate hard blocks.
   - Ambiguous or weak signals are combined via weighted aggregation and agreement boosts.
   - Weak statistical anomalies alone never trigger an automatic block.

3. **Strict Zero-Trust Model Flow:**
   User Input ➔ 6-Layer Firewall ➔ Decision Engine ➔ Gemini Provider (if permitted) ➔ Output Re-Analysis ➔ Sanitized Safe Response.
   Model outputs are never returned blindly without passing through the secondary output defense layer.

4. **Zero Frontend Secrets:**
   The browser communicates strictly with the FastAPI backend. `GEMINI_API_KEY` is loaded exclusively from the server environment and never exposed to the client.

5. **Real-time Pipeline Transparency:**
   Every single pipeline step emits real SSE events backed by database records. There are no timers, fake progress bars, or simulated numbers.

---

## Component Architecture

### 1. Security Firewall Engine (`app/firewall/`)
- **`engine.py`**: Coordinates the 6 layers, computes the weighted risk score, confidence rating, and produces a `SecurityDecision`.
- **`rule_based.py`**: Layer 1 regex pattern matcher covering instruction override, role manipulation, prompt leaking, and safety bypass.
- **`sql_intent.py`**: Layer 2 SQL AST analyzer using `sqlglot` for syntax trees and injection heuristics.
- **`ml_classifier.py`**: Layer 3 scikit-learn TF-IDF + SGDClassifier model trained on adversarial attack corpora.
- **`guardrails.py`**: Layer 4 policy enforcement checking structural boundaries, role preservation, and encoding obfuscation.
- **`chunk_anomaly.py`**: Layer 5 sliding-window analyzer tracking spatial concentration of suspicious tokens.
- **`perplexity.py`**: Layer 6 statistical proxy examining Shannon entropy, character diversity, and token distribution.
- **`output_analyzer.py`**: Post-generation scanner detecting credential leakage, system prompt echoes, and unsafe patterns.

### 2. LLM Provider (`app/llm/`)
- **`base.py`**: Abstract `LLMProvider` interface.
- **`gemini_provider.py`**: Server-side Google Gemini client using the `google-genai` SDK. Model name is configurable via `GEMINI_MODEL`.

### 3. Data Persistence (`app/models/`, `app/database.py`)
- SQLite via SQLAlchemy 2.0 async ORM and `aiosqlite`.
- Models: `RequestLog`, `SecurityEvent`, `LayerResult`.

### 4. Real-time Event Streaming (`app/services/event_bus.py`, `app/routers/events.py`)
- In-memory async fan-out pub-sub queue feeding the `/api/events/stream` Server-Sent Events endpoint.
