"""
Security Decision Engine — replaces simple max(score) logic.

Two-stage decision process:
  A. Hard Security Violations — deterministic findings that immediately BLOCK
  B. Multi-Signal Risk — weighted aggregation of all 6 layer scores

Evidence classification matters:
  - deterministic: confirmed attack → hard block
  - strong_semantic: high-confidence semantic signal → weighted heavily
  - weak_anomaly: statistical/contextual signal → weighted lightly, never blocks alone

Weights and thresholds are loaded from configuration (never hard-coded).
"""

import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from app.firewall.base_layer import LayerResult
from app.firewall.rule_based import RuleBasedLayer
from app.firewall.sql_intent import SQLIntentLayer
from app.firewall.ml_classifier import MLClassifierLayer
from app.firewall.guardrails import GuardrailsLayer
from app.firewall.chunk_anomaly import ChunkAnomalyLayer
from app.firewall.perplexity import PerplexityLayer
from app.config import settings


@dataclass
class SecurityDecision:
    decision: str  # ALLOW / SANITIZE / BLOCK
    risk_score: float
    confidence: float
    reason: str
    hard_block: bool
    triggered_layers: List[str] = field(default_factory=list)
    layer_results: List[LayerResult] = field(default_factory=list)
    total_latency_ms: float = 0.0


# Map layer names to their config weight keys
LAYER_WEIGHT_MAP = {
    "Rule-Based Detection": "RULE_WEIGHT",
    "SQL & Intent Analysis": "SQL_WEIGHT",
    "ML Safety Classifier": "ML_WEIGHT",
    "Prompt-Injection Guardrails": "GUARDRAIL_WEIGHT",
    "Chunk Anomaly Analysis": "CHUNK_WEIGHT",
    "Perplexity / Statistical Anomaly Analysis": "ANOMALY_WEIGHT",
}


class FirewallEngine:
    """
    Orchestrates all 6 security layers and produces a SecurityDecision.
    This is an orchestration/decision component, NOT a 7th detection layer.
    """

    def __init__(self):
        self.layers = [
            RuleBasedLayer(),        # Layer 1
            SQLIntentLayer(),        # Layer 2
            MLClassifierLayer(),     # Layer 3
            GuardrailsLayer(),       # Layer 4
            ChunkAnomalyLayer(),     # Layer 5
            PerplexityLayer(),       # Layer 6
        ]

    def _get_weight(self, layer_name: str) -> float:
        """Get configurable weight for a layer from settings."""
        attr = LAYER_WEIGHT_MAP.get(layer_name, "")
        return getattr(settings, attr, 0.1) if attr else 0.1

    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None,
                      event_callback=None) -> SecurityDecision:
        """
        Run all 6 layers and produce a SecurityDecision.

        Args:
            content: The user prompt to analyze.
            context: Optional context dict.
            event_callback: Async callable for emitting pipeline events.

        Returns:
            SecurityDecision with full layer results preserved.
        """
        overall_start = time.perf_counter()
        layer_results: List[LayerResult] = []
        triggered_layers: List[str] = []

        # --- Phase 1: Run all 6 detection layers ---
        for layer in self.layers:
            if event_callback:
                await event_callback("LAYER_STARTED", layer_name=layer.name)

            result = await layer.analyze(content, context)
            layer_results.append(result)

            if event_callback:
                await event_callback(
                    "LAYER_COMPLETED",
                    layer_name=layer.name,
                    score=result.score,
                    passed=result.passed,
                    latency_ms=result.latency_ms,
                )

            if not result.passed:
                triggered_layers.append(result.layer_name)

        # --- Phase 2A: Check for hard security violations ---
        hard_block_results = [r for r in layer_results if r.hard_block_trigger]
        if hard_block_results:
            total_latency = (time.perf_counter() - overall_start) * 1000
            reasons = [r.details.get("reason", r.layer_name) for r in hard_block_results]
            hard_block_layers = [r.layer_name for r in hard_block_results]

            decision = SecurityDecision(
                decision="BLOCK",
                risk_score=max(r.score for r in hard_block_results),
                confidence=0.98,
                reason=f"Hard security violation: {'; '.join(reasons)}",
                hard_block=True,
                triggered_layers=triggered_layers if triggered_layers else hard_block_layers,
                layer_results=layer_results,
                total_latency_ms=round(total_latency, 2),
            )

            if event_callback:
                await event_callback(
                    "SECURITY_DECISION",
                    decision=decision.decision,
                    risk_score=decision.risk_score,
                    hard_block=True,
                    reason=decision.reason,
                )
            return decision

        # --- Phase 2B: Multi-signal weighted risk aggregation ---
        weighted_sum = 0.0
        total_weight = 0.0
        deterministic_scores = []
        strong_scores = []
        weak_scores = []

        for result in layer_results:
            weight = self._get_weight(result.layer_name)

            # Classify evidence strength
            if result.evidence_type == "deterministic":
                deterministic_scores.append(result.score)
                # Deterministic evidence gets full weight
                weighted_sum += result.score * weight
                total_weight += weight
            elif result.evidence_type == "strong_semantic":
                strong_scores.append(result.score)
                weighted_sum += result.score * weight
                total_weight += weight
            else:
                weak_scores.append(result.score)
                # Weak anomaly evidence is discounted — cannot dominate the decision
                discounted_weight = weight * 0.5
                weighted_sum += result.score * discounted_weight
                total_weight += discounted_weight

        # Compute combined risk score
        if total_weight > 0:
            risk_score = weighted_sum / total_weight
        else:
            risk_score = 0.0

        # Boost if multiple strong signals agree
        strong_agreement_count = sum(1 for s in strong_scores if s >= 0.5) + \
                                 sum(1 for s in deterministic_scores if s >= 0.5)
        if strong_agreement_count >= 2:
            agreement_boost = min(0.15, strong_agreement_count * 0.05)
            risk_score = min(1.0, risk_score + agreement_boost)

        # Confidence: higher when more layers agree
        failing_count = len(triggered_layers)
        total_layers = len(layer_results)
        agreement_ratio = failing_count / total_layers if total_layers > 0 else 0
        confidence = min(0.99, 0.5 + agreement_ratio * 0.5)

        # If only weak anomaly signals are elevated, reduce confidence
        if not deterministic_scores and not any(s >= 0.5 for s in strong_scores):
            confidence = min(confidence, 0.6)

        risk_score = round(min(1.0, risk_score), 4)
        confidence = round(confidence, 4)

        # --- Phase 3: Make decision ---
        sanitize_threshold = settings.SANITIZE_THRESHOLD
        block_threshold = settings.BLOCK_THRESHOLD

        if risk_score >= block_threshold:
            decision_str = "BLOCK"
        elif risk_score >= sanitize_threshold:
            decision_str = "SANITIZE"
        else:
            decision_str = "ALLOW"

        # Generate explanation
        reason = self._build_reason(decision_str, risk_score, triggered_layers, layer_results)

        total_latency = (time.perf_counter() - overall_start) * 1000
        decision = SecurityDecision(
            decision=decision_str,
            risk_score=risk_score,
            confidence=confidence,
            reason=reason,
            hard_block=False,
            triggered_layers=triggered_layers,
            layer_results=layer_results,
            total_latency_ms=round(total_latency, 2),
        )

        if event_callback:
            await event_callback(
                "SECURITY_DECISION",
                decision=decision.decision,
                risk_score=decision.risk_score,
                hard_block=False,
                reason=decision.reason,
            )

        return decision

    def _build_reason(self, decision: str, risk_score: float,
                      triggered_layers: List[str], results: List[LayerResult]) -> str:
        """Build a human-readable explanation of the security decision."""
        if decision == "ALLOW":
            return f"All security layers passed. Combined risk score: {risk_score:.2f}."

        if not triggered_layers:
            return f"Elevated combined risk score ({risk_score:.2f}) from multiple weak signals."

        # Summarize what was detected
        categories = set()
        for r in results:
            if not r.passed:
                cats = r.details.get("categories", [])
                if cats:
                    categories.update(cats)
                violations = r.details.get("violations", [])
                for v in violations:
                    if isinstance(v, dict) and "check" in v:
                        categories.add(v["check"])

        layers_str = ", ".join(triggered_layers)
        cats_str = ", ".join(categories) if categories else "suspicious content"

        return (
            f"Multiple security layers detected {cats_str}. "
            f"Triggered layers: {layers_str}. "
            f"Combined risk score: {risk_score:.2f}."
        )
