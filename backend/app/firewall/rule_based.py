"""
Layer 1: Rule-Based Pattern Check
Regex attack signatures for known prompt injection patterns.
Deterministic matching — high-confidence hits produce strong semantic evidence.
"""

import re
import time
from typing import Any, Dict, List, Optional
from app.firewall.base_layer import SecurityLayer, LayerResult

# Known prompt injection patterns with severity classifications
ATTACK_PATTERNS: List[Dict[str, Any]] = [
    # --- Instruction Override (deterministic) ---
    {"pattern": r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directions?)",
     "category": "instruction_override", "severity": "critical", "weight": 0.9},
    {"pattern": r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
     "category": "instruction_override", "severity": "critical", "weight": 0.9},
    {"pattern": r"forget\s+(everything|all|your)\s+(you\s+)?(know|were told|instructions?)",
     "category": "instruction_override", "severity": "critical", "weight": 0.85},
    {"pattern": r"override\s+(your|the|all)\s+(instructions?|rules?|safety|guidelines?|restrictions?)",
     "category": "instruction_override", "severity": "critical", "weight": 0.9},
    {"pattern": r"new\s+instructions?\s*[:=]",
     "category": "instruction_override", "severity": "high", "weight": 0.8},

    # --- Role Manipulation ---
    {"pattern": r"you\s+are\s+now\s+(a|an|the|my)\s+",
     "category": "role_manipulation", "severity": "high", "weight": 0.85},
    {"pattern": r"act\s+as\s+(a|an|if\s+you\s+were)\s+",
     "category": "role_manipulation", "severity": "high", "weight": 0.7},
    {"pattern": r"pretend\s+(to\s+be|you\s+are|that)",
     "category": "role_manipulation", "severity": "high", "weight": 0.75},
    {"pattern": r"switch\s+to\s+.{0,30}mode",
     "category": "role_manipulation", "severity": "high", "weight": 0.8},
    {"pattern": r"enter\s+(developer|debug|admin|god|sudo|jailbreak)\s+mode",
     "category": "role_manipulation", "severity": "critical", "weight": 0.95},
    {"pattern": r"\bDAN\b.*\bdo\s+anything\s+now\b",
     "category": "role_manipulation", "severity": "critical", "weight": 0.95},

    # --- System Prompt Extraction ---
    {"pattern": r"(reveal|show|display|print|output|repeat|tell\s+me)\s+(the|your)\s+(system|initial|original)\s+(prompt|instructions?|message)",
     "category": "system_prompt_extraction", "severity": "critical", "weight": 0.9},
    {"pattern": r"what\s+(are|is|were)\s+your\s+(system|initial|original|first)\s+(prompt|instructions?|message|rules?)",
     "category": "system_prompt_extraction", "severity": "high", "weight": 0.8},
    {"pattern": r"(print|echo|output)\s+(your|the)\s+(instructions?|prompt|rules?|configuration)",
     "category": "system_prompt_extraction", "severity": "high", "weight": 0.85},

    # --- Delimiter / Context Injection ---
    {"pattern": r"```\s*(system|admin|root|instructions?)\s*\n",
     "category": "delimiter_injection", "severity": "high", "weight": 0.8},
    {"pattern": r"<\s*(system|instruction|admin|prompt)\s*>",
     "category": "delimiter_injection", "severity": "high", "weight": 0.8},
    {"pattern": r"\[SYSTEM\]|\[INST\]|\[\/INST\]|\[ADMIN\]",
     "category": "delimiter_injection", "severity": "high", "weight": 0.85},
    {"pattern": r"---\s*(begin|start|new)\s+(system|admin)\s*(prompt|instruction|message)\s*---",
     "category": "delimiter_injection", "severity": "high", "weight": 0.85},

    # --- Encoding / Obfuscation ---
    {"pattern": r"base64[:=]\s*[A-Za-z0-9+/]{20,}",
     "category": "encoding_attack", "severity": "medium", "weight": 0.6},
    {"pattern": r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}",
     "category": "encoding_attack", "severity": "medium", "weight": 0.6},
    {"pattern": r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,}",
     "category": "encoding_attack", "severity": "medium", "weight": 0.6},

    # --- Data Exfiltration ---
    {"pattern": r"(send|transmit|post|exfiltrate|forward)\s+.{0,40}(data|info|credentials|password|key|secret|token)\s+(to|via|through)",
     "category": "data_exfiltration", "severity": "critical", "weight": 0.9},
    {"pattern": r"(extract|steal|capture|harvest)\s+.{0,30}(password|credentials|api.?key|secret|token|ssn|credit.?card)",
     "category": "data_exfiltration", "severity": "critical", "weight": 0.9},

    # --- Safety Bypass ---
    {"pattern": r"(bypass|disable|turn\s+off|remove|ignore)\s+(your\s+)?(safety|content|ethical|security)\s+(filter|check|guard|restriction|policy|guideline)",
     "category": "safety_bypass", "severity": "critical", "weight": 0.9},
    {"pattern": r"no\s+(filter|restriction|limitation|safety|censorship|moderation)",
     "category": "safety_bypass", "severity": "high", "weight": 0.75},
    {"pattern": r"without\s+(any\s+)?(filter|restriction|limitation|safety|censorship|moderation)",
     "category": "safety_bypass", "severity": "high", "weight": 0.75},

    # --- Prompt Leaking ---
    {"pattern": r"(before|above)\s+.{0,20}(text|message|conversation|prompt)\s+.{0,20}(repeat|copy|paste|show)",
     "category": "prompt_leaking", "severity": "high", "weight": 0.7},
    {"pattern": r"(everything|all)\s+(above|before|preceding)\s+this",
     "category": "prompt_leaking", "severity": "medium", "weight": 0.65},

    # --- Multi-turn / Indirect ---
    {"pattern": r"(in\s+the\s+)?(previous|last|earlier)\s+(conversation|turn|message).*said.*",
     "category": "context_manipulation", "severity": "medium", "weight": 0.5},
    {"pattern": r"<\s*ignore\s*>.*<\s*/\s*ignore\s*>",
     "category": "indirect_injection", "severity": "high", "weight": 0.8},
]

# Pre-compile all patterns
_COMPILED = [(re.compile(p["pattern"], re.IGNORECASE | re.DOTALL), p) for p in ATTACK_PATTERNS]


class RuleBasedLayer(SecurityLayer):
    """Layer 1: Rule-Based Pattern Check — regex attack signature matching."""

    @property
    def name(self) -> str:
        return "Rule-Based Detection"

    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        start = time.perf_counter()
        matched_rules = []
        categories_hit = set()
        max_weight = 0.0

        for compiled_re, meta in _COMPILED:
            matches = compiled_re.findall(content)
            if matches:
                matched_rules.append({
                    "pattern": meta["pattern"][:60],
                    "category": meta["category"],
                    "severity": meta["severity"],
                    "weight": meta["weight"],
                    "match_count": len(matches),
                })
                categories_hit.add(meta["category"])
                max_weight = max(max_weight, meta["weight"])

        # Score: use the highest-weight match, boosted slightly by breadth of categories
        if matched_rules:
            breadth_boost = min(0.1, len(categories_hit) * 0.03)
            score = min(1.0, max_weight + breadth_boost)
        else:
            score = 0.0

        passed = score < 0.5
        latency = (time.perf_counter() - start) * 1000

        # Determine evidence type
        has_critical = any(r["severity"] == "critical" for r in matched_rules)
        if has_critical and score >= 0.85:
            evidence_type = "deterministic"
        elif score >= 0.6:
            evidence_type = "strong_semantic"
        else:
            evidence_type = "weak_anomaly"

        return LayerResult(
            layer_name=self.name,
            passed=passed,
            score=round(score, 4),
            details={
                "matched_rules": matched_rules,
                "categories": list(categories_hit),
                "total_matches": len(matched_rules),
                "reason": f"Matched {len(matched_rules)} attack pattern(s) across {len(categories_hit)} category(ies)."
                          if matched_rules else "No known attack patterns detected.",
            },
            latency_ms=round(latency, 2),
            evidence_type=evidence_type,
            hard_block_trigger=False,  # Rule-based alone does not hard-block; decision engine decides
        )
