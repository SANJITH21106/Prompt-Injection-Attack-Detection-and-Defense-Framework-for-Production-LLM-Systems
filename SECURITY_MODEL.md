# Security Model

## Overview

The security model implements a multi-layered defense-in-depth perimeter around LLM interactions. It balances low false-positive rates on complex technical prompts with resilient blocking of adversarial and evasive attacks.

---

## 1. Threat Taxonomy

The firewall defends against the following threat categories:

| Threat Category | Description | Primary Defense Layers |
|-----------------|-------------|------------------------|
| **Direct Prompt Injection** | Explicit commands attempting to override system behavior (e.g. "Ignore previous instructions") | Layer 1 (Rule), Layer 3 (ML), Layer 4 (Guardrails) |
| **Role Manipulation / Jailbreak** | Framing the model into an unrestricted persona (e.g. DAN, developer mode) | Layer 1 (Rule), Layer 4 (Guardrails), Layer 3 (ML) |
| **System Prompt Extraction** | Attempts to leak instructions or hidden context | Layer 1 (Rule), Layer 4 (Guardrails), Output Analyzer |
| **SQL Injection** | Tautologies, stacked queries, destructive operations | Layer 2 (SQL & Intent via sqlglot) |
| **Context Manipulation & Delimiters** | Fake system tokens (e.g., `[SYSTEM]`, `--- begin admin ---`) | Layer 1 (Rule), Layer 4 (Guardrails), Layer 5 (Chunk) |
| **Statistical Anomalies** | Random character sequences, high-entropy obfuscation | Layer 6 (Statistical Anomaly Proxy) |
| **Sensitive Data Leakage** | Exposure of secrets, API keys, credentials in generated output | Output Re-Analysis |

---

## 2. Evidence Classification

Layer findings are categorized into three distinct evidence tiers:

1. **`deterministic`**:
   - High-certainty findings with near-zero false-positive rate.
   - Examples: Syntactically parsed destructive SQL (`DROP TABLE`), 3+ simultaneous severe guardrail breaches.
   - Action: May trigger an immediate `hard_block`.

2. **`strong_semantic`**:
   - High-confidence lexical or semantic signals (e.g., confirmed injection signatures, ML classifier high confidence).
   - Weighted heavily during multi-signal risk aggregation.

3. **`weak_anomaly`**:
   - Contextual, structural, or statistical deviation signals (e.g., Shannon entropy fluctuations, punctuation clusters).
   - **Crucial Rule:** Weak anomalies are weighted lightly and **NEVER** trigger an automatic block on their own.

---

## 3. Decision Engine & Risk Aggregation

The Security Decision Engine runs a two-stage evaluation:

### Stage A: Hard Security Violations Check
If any layer reports `hard_block_trigger = True`:
- Decision: `BLOCK`
- `hard_block: True`
- `confidence: 0.98`
- `triggered_layers`: All layers that exhibited failure or security evidence are preserved.

### Stage B: Weighted Multi-Signal Aggregation
When no hard block is present, risk scores ($S_i$) and weights ($W_i$) from all 6 layers are aggregated:

$$\text{Combined Risk} = \frac{\sum_{i=1}^{6} S_i \cdot W'_i}{\sum_{i=1}^{6} W'_i}$$

where $W'_i = W_i$ for deterministic and strong semantic signals, and $W'_i = 0.5 \cdot W_i$ for weak anomalies.

If multiple strong signals agree ($\ge 2$ strong signals with $S \ge 0.5$), an **agreement boost** is applied:
$$\text{Risk} \leftarrow \min(1.0, \text{Risk} + \text{boost})$$

### Risk Bands and Decisions:
- **Low Risk** ($\text{Risk} < 0.45$): `ALLOW`
- **Moderate Risk** ($0.45 \le \text{Risk} < 0.75$): `SANITIZE`
  - Strips injection markers and malicious tags before forwarding to LLM.
- **High Risk** ($\text{Risk} \ge 0.75$): `BLOCK`

---

## 4. Output Re-Analysis

All model generations pass through secondary analysis before release:
- Secret / API key patterns (AWS keys, generic Bearer tokens, private keys)
- Prompt leakage indicators
- Destructive code suggestions
- If sensitive patterns are detected:
  - Masked / sanitized for moderate severity.
  - Replaced with a safe refusal for high severity ($\ge 0.8$).
