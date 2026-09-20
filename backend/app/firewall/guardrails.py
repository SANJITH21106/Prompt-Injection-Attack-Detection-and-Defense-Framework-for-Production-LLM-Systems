"""
Layer 4: Prompt-Injection Guardrails
Security policy enforcement — detects instruction override, role manipulation,
system prompt leakage, multi-turn manipulation, and encoding/obfuscation.
"""

import re
import base64
import time
from typing import Any, Dict, List, Optional
from app.firewall.base_layer import SecurityLayer, LayerResult


class GuardrailsLayer(SecurityLayer):
    """Layer 4: Prompt-Injection Guardrails — policy enforcement rules."""

    @property
    def name(self) -> str:
        return "Prompt-Injection Guardrails"

    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        start = time.perf_counter()
        violations: List[Dict[str, Any]] = []
        max_severity_score = 0.0

        # --- Check 1: Instruction Override Detection ---
        override_score = self._check_instruction_override(content)
        if override_score > 0:
            violations.append({
                "check": "instruction_override",
                "score": override_score,
                "description": "Detected attempt to override model instructions.",
            })
            max_severity_score = max(max_severity_score, override_score)

        # --- Check 2: Role Manipulation Detection ---
        role_score = self._check_role_manipulation(content)
        if role_score > 0:
            violations.append({
                "check": "role_manipulation",
                "score": role_score,
                "description": "Detected attempt to redefine model role or persona.",
            })
            max_severity_score = max(max_severity_score, role_score)

        # --- Check 3: System Prompt Leakage ---
        leakage_score = self._check_system_prompt_leakage(content)
        if leakage_score > 0:
            violations.append({
                "check": "system_prompt_leakage",
                "score": leakage_score,
                "description": "Detected attempt to extract system prompt or instructions.",
            })
            max_severity_score = max(max_severity_score, leakage_score)

        # --- Check 4: Encoding / Obfuscation ---
        encoding_score = self._check_encoding_obfuscation(content)
        if encoding_score > 0:
            violations.append({
                "check": "encoding_obfuscation",
                "score": encoding_score,
                "description": "Detected potentially obfuscated or encoded malicious content.",
            })
            max_severity_score = max(max_severity_score, encoding_score)

        # --- Check 5: Multi-turn Context Manipulation ---
        context_score = self._check_context_manipulation(content)
        if context_score > 0:
            violations.append({
                "check": "context_manipulation",
                "score": context_score,
                "description": "Detected multi-turn context manipulation attempt.",
            })
            max_severity_score = max(max_severity_score, context_score)

        # Combine: average of violation scores weighted by count
        if violations:
            avg_score = sum(v["score"] for v in violations) / len(violations)
            # Boost for multiple violations
            multi_boost = min(0.15, (len(violations) - 1) * 0.05)
            score = min(1.0, max(avg_score, max_severity_score * 0.9) + multi_boost)
        else:
            score = 0.0

        passed = score < 0.5
        latency = (time.perf_counter() - start) * 1000

        # Evidence classification
        if len(violations) >= 3 and max_severity_score >= 0.8:
            evidence_type = "deterministic"
            hard_block = True
        elif max_severity_score >= 0.7:
            evidence_type = "strong_semantic"
            hard_block = False
        else:
            evidence_type = "weak_anomaly"
            hard_block = False

        return LayerResult(
            layer_name=self.name,
            passed=passed,
            score=round(score, 4),
            details={
                "violations": violations,
                "violation_count": len(violations),
                "reason": f"Detected {len(violations)} guardrail violation(s)."
                          if violations else "No guardrail violations detected.",
            },
            latency_ms=round(latency, 2),
            evidence_type=evidence_type,
            hard_block_trigger=hard_block,
        )

    def _check_instruction_override(self, content: str) -> float:
        patterns = [
            (r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?|prompt|training)", 0.9),
            (r"new\s+(instructions?|rules?|directives?)\s*[:=]", 0.8),
            (r"(you\s+must|you\s+will|you\s+shall)\s+(now\s+)?(obey|follow|comply|listen)", 0.85),
            (r"from\s+now\s+on\s*,?\s*(you|ignore|your|respond)", 0.8),
            (r"(stop|cease)\s+(being|acting|following)\s+(a|an|your|the)", 0.7),
        ]
        return self._max_pattern_score(content, patterns)

    def _check_role_manipulation(self, content: str) -> float:
        patterns = [
            (r"you\s+are\s+now\s+(a|an|the|my)\b", 0.8),
            (r"(act|behave|pretend|respond)\s+(as|like)\s+(a|an|if)", 0.7),
            (r"(enter|switch\s+to|activate|enable)\s+.{0,20}(mode|persona|character)", 0.8),
            (r"\b(DAN|jailbreak|uncensored|unfiltered|unrestricted)\b", 0.85),
            (r"(no\s+longer|not\s+anymore)\s+(a|an)\s+(safe|helpful|harmless)", 0.85),
        ]
        return self._max_pattern_score(content, patterns)

    def _check_system_prompt_leakage(self, content: str) -> float:
        patterns = [
            (r"(reveal|show|display|print|output|repeat|share)\s+(your|the)\s+(system|initial|original|hidden)\s+(prompt|instructions?|message|configuration)", 0.9),
            (r"what\s+(are|is|were)\s+your\s+(system|initial|original|hidden|secret)\s+(prompt|instructions?|rules?)", 0.85),
            (r"(copy|paste|dump|echo)\s+(your|the|all)\s+(instructions?|prompt|rules?|config)", 0.85),
            (r"(beginning|start)\s+of\s+(this|your|the)\s+(conversation|chat|session|prompt)", 0.6),
        ]
        return self._max_pattern_score(content, patterns)

    def _check_encoding_obfuscation(self, content: str) -> float:
        score = 0.0

        # Check for base64-encoded content that might decode to injection
        b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
        for match in b64_pattern:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore").lower()
                injection_keywords = ["ignore", "override", "system", "prompt", "instruction",
                                      "bypass", "admin", "sudo", "hack", "password"]
                if any(kw in decoded for kw in injection_keywords):
                    score = max(score, 0.85)
                else:
                    score = max(score, 0.3)  # Base64 present but benign
            except Exception:
                pass

        # Unicode tricks
        if re.search(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]', content):
            score = max(score, 0.7)

        # Excessive escape sequences
        escape_count = len(re.findall(r'\\[xuU][0-9a-fA-F]+', content))
        if escape_count >= 5:
            score = max(score, 0.6)

        return score

    def _check_context_manipulation(self, content: str) -> float:
        patterns = [
            (r"(in|during)\s+(the|our)\s+(previous|last|earlier)\s+(conversation|chat|turn)\s+you\s+(said|agreed|confirmed|promised)", 0.7),
            (r"(remember|recall)\s+when\s+you\s+(said|told|agreed|confirmed)", 0.6),
            (r"you\s+(already|previously)\s+(agreed|confirmed|said|told|promised)\s+(to|that|you)", 0.7),
            (r"we\s+(already|previously)\s+(agreed|decided|established)\s+(that|to)", 0.5),
        ]
        return self._max_pattern_score(content, patterns)

    @staticmethod
    def _max_pattern_score(content: str, patterns: list) -> float:
        max_score = 0.0
        for pattern, weight in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                max_score = max(max_score, weight)
        return max_score
