"""
Layer 6: Perplexity / Statistical Anomaly Analysis

IMPORTANT: This layer uses STATISTICAL PROXY indicators, NOT true model perplexity.
True token-level perplexity requires a language model to compute log-likelihoods,
which is not available in the current lightweight implementation.

The analysis_type field in results will always be "statistical_proxy" unless
an actual perplexity-capable model is integrated in the future.

Statistical indicators used:
- Repetitive sequence detection
- Abnormal character distribution
- Encoding/obfuscation indicators
- Unusual token/word distribution
- Suspicious adversarial suffix patterns
- Excessive special-character patterns

This layer produces WEAK ANOMALY evidence. It should never independently cause
a BLOCK decision without corroboration from other layers.
"""

import re
import math
import time
from collections import Counter
from typing import Any, Dict, Optional
from app.firewall.base_layer import SecurityLayer, LayerResult


class PerplexityLayer(SecurityLayer):
    """
    Layer 6: Perplexity / Statistical Anomaly Analysis.
    Uses statistical proxies — does NOT compute true model perplexity.
    """

    @property
    def name(self) -> str:
        return "Perplexity / Statistical Anomaly Analysis"

    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        start = time.perf_counter()

        if not content.strip():
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(
                layer_name=self.name, passed=True, score=0.0,
                details={"analysis_type": "statistical_proxy", "reason": "Empty content."},
                latency_ms=round(latency, 2), evidence_type="weak_anomaly",
            )

        # Compute individual statistical indicators
        repetition_score = self._repetition_analysis(content)
        encoding_score = self._encoding_analysis(content)
        char_anomaly_score = self._character_anomaly(content)
        token_dist_score = self._token_distribution(content)
        suffix_score = self._adversarial_suffix_detection(content)
        special_char_score = self._special_character_analysis(content)

        # Weighted combination of indicators (not a simple max)
        indicator_weights = {
            "repetition": 0.2,
            "encoding": 0.2,
            "char_anomaly": 0.15,
            "token_distribution": 0.15,
            "suffix": 0.2,
            "special_char": 0.1,
        }
        weighted_sum = (
            repetition_score * indicator_weights["repetition"]
            + encoding_score * indicator_weights["encoding"]
            + char_anomaly_score * indicator_weights["char_anomaly"]
            + token_dist_score * indicator_weights["token_distribution"]
            + suffix_score * indicator_weights["suffix"]
            + special_char_score * indicator_weights["special_char"]
        )

        # Normalize
        score = min(1.0, weighted_sum)
        passed = score < 0.5
        latency = (time.perf_counter() - start) * 1000

        return LayerResult(
            layer_name=self.name,
            passed=passed,
            score=round(score, 4),
            details={
                "analysis_type": "statistical_proxy",
                "note": "This is a statistical anomaly analysis, NOT true language-model perplexity.",
                "repetition_score": round(repetition_score, 4),
                "encoding_score": round(encoding_score, 4),
                "character_anomaly_score": round(char_anomaly_score, 4),
                "token_distribution_score": round(token_dist_score, 4),
                "adversarial_suffix_score": round(suffix_score, 4),
                "special_character_score": round(special_char_score, 4),
                "reason": self._generate_reason(score, {
                    "repetition": repetition_score,
                    "encoding": encoding_score,
                    "char_anomaly": char_anomaly_score,
                    "token_distribution": token_dist_score,
                    "suffix": suffix_score,
                    "special_char": special_char_score,
                }),
            },
            latency_ms=round(latency, 2),
            evidence_type="weak_anomaly",  # Always weak — statistical proxy only
            hard_block_trigger=False,  # Never hard-blocks independently
        )

    def _repetition_analysis(self, content: str) -> float:
        """Detect unusually repetitive sequences."""
        if len(content) < 10:
            return 0.0

        # Character-level repetition
        chars = list(content)
        repeated_runs = 0
        max_run = 0
        current_run = 1
        for i in range(1, len(chars)):
            if chars[i] == chars[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                if current_run >= 5:
                    repeated_runs += 1
                current_run = 1

        # Word-level repetition
        words = content.lower().split()
        if len(words) > 3:
            word_counts = Counter(words)
            most_common_ratio = word_counts.most_common(1)[0][1] / len(words) if words else 0
        else:
            most_common_ratio = 0

        # N-gram repetition (3-grams)
        trigrams = [content[i:i+3] for i in range(len(content) - 2)]
        if trigrams:
            tri_counts = Counter(trigrams)
            tri_repetition = tri_counts.most_common(1)[0][1] / len(trigrams) if trigrams else 0
        else:
            tri_repetition = 0

        char_score = min(1.0, max_run / 20)
        word_score = min(1.0, most_common_ratio * 2) if most_common_ratio > 0.3 else 0.0
        tri_score = min(1.0, tri_repetition * 3) if tri_repetition > 0.15 else 0.0

        return max(char_score, word_score, tri_score)

    def _encoding_analysis(self, content: str) -> float:
        """Detect encoded/obfuscated content."""
        score = 0.0

        # Base64 patterns
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
        if b64_matches:
            score = max(score, min(1.0, len(b64_matches) * 0.3))

        # Hex sequences
        hex_matches = re.findall(r'(?:0x[0-9a-fA-F]{2}[\s,]*){4,}', content)
        if hex_matches:
            score = max(score, 0.5)

        # Escape sequences
        escape_count = len(re.findall(r'\\[xuU][0-9a-fA-F]+', content))
        if escape_count >= 3:
            score = max(score, min(1.0, escape_count * 0.15))

        # Unicode control characters
        control_chars = len(re.findall(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]', content))
        if control_chars > 0:
            score = max(score, min(1.0, control_chars * 0.2))

        return score

    def _character_anomaly(self, content: str) -> float:
        """Detect abnormal character distribution."""
        if len(content) < 5:
            return 0.0

        # Character entropy
        char_counts = Counter(content)
        total = len(content)
        entropy = -sum((c / total) * math.log2(c / total) for c in char_counts.values() if c > 0)

        # Typical English text entropy is ~4.0-5.0 bits per character
        # Very low entropy (repetitive) or very high entropy (random) are suspicious
        if entropy < 2.0 and len(content) > 50:
            return min(1.0, (2.0 - entropy) / 2.0)
        elif entropy > 6.0:
            return min(1.0, (entropy - 6.0) / 2.0)

        # Ratio of non-ASCII characters
        non_ascii = sum(1 for c in content if ord(c) > 127)
        non_ascii_ratio = non_ascii / total
        if non_ascii_ratio > 0.3:
            return min(1.0, non_ascii_ratio)

        return 0.0

    def _token_distribution(self, content: str) -> float:
        """Analyze word/token distribution for anomalies."""
        words = re.findall(r'\b\w+\b', content.lower())
        if len(words) < 5:
            return 0.0

        # Vocabulary richness: unique words / total words
        unique_ratio = len(set(words)) / len(words)

        # Very low vocabulary richness is suspicious (repetitive attack payload)
        if unique_ratio < 0.3 and len(words) > 10:
            return min(1.0, (0.3 - unique_ratio) * 3)

        # Average word length anomaly
        avg_len = sum(len(w) for w in words) / len(words)
        if avg_len > 15:  # Very long "words" suggest encoded content
            return min(1.0, (avg_len - 15) / 10)

        return 0.0

    def _adversarial_suffix_detection(self, content: str) -> float:
        """Detect adversarial suffix patterns (GCG-style attacks)."""
        # Look for strings of seemingly random tokens often used in adversarial attacks
        # These tend to have unusual character patterns

        # Long strings of mixed-case random-looking text
        random_blocks = re.findall(r'[a-zA-Z]{15,}', content)
        for block in random_blocks:
            # Check if block looks random (high case alternation, unusual patterns)
            case_changes = sum(1 for i in range(1, len(block)) if block[i].isupper() != block[i-1].isupper())
            if case_changes / len(block) > 0.4:
                return min(1.0, case_changes / len(block))

        # Sequences of special tokens or unusual symbol patterns
        weird_sequences = re.findall(r'[^\w\s]{5,}', content)
        if len(weird_sequences) >= 2:
            return min(1.0, len(weird_sequences) * 0.2)

        return 0.0

    def _special_character_analysis(self, content: str) -> float:
        """Detect excessive special character patterns."""
        if len(content) < 10:
            return 0.0

        special_chars = sum(1 for c in content if not c.isalnum() and not c.isspace())
        ratio = special_chars / len(content)

        # High special character ratio is mildly suspicious
        if ratio > 0.4:
            return min(1.0, (ratio - 0.4) * 2)
        return 0.0

    def _generate_reason(self, score: float, indicators: Dict[str, float]) -> str:
        """Generate human-readable reason from indicator scores."""
        if score < 0.1:
            return "No significant statistical anomalies detected."

        high_indicators = [name for name, val in indicators.items() if val >= 0.3]
        if high_indicators:
            return (
                f"Statistical anomaly score: {score:.2f}. "
                f"Elevated indicators: {', '.join(high_indicators)}. "
                f"Note: these are statistical proxies, not true model perplexity."
            )
        return f"Mild statistical anomaly detected (score: {score:.2f}). Within normal range."
