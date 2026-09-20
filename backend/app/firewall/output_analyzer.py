"""
Output Re-Analysis — scans Gemini's response before returning to the user.
Checks for: sensitive data patterns, prompt leakage, unsafe content.
Can sanitize (redact) or flag the response.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class OutputAnalysisResult:
    safe: bool
    sanitized_text: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    score: float = 0.0
    latency_ms: float = 0.0


# Sensitive data patterns for redaction
SENSITIVE_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN", "***-**-****"),
    (re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'), "credit_card", "****-****-****-****"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "email", "[EMAIL REDACTED]"),
    (re.compile(r'\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\'"]?[\w\-\.]{10,}[\'"]?', re.IGNORECASE),
     "api_key", "[API KEY REDACTED]"),
    (re.compile(r'\b(?:password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]{6,}[\'"]?', re.IGNORECASE),
     "password", "[PASSWORD REDACTED]"),
    (re.compile(r'\b(?:sk-|pk_live_|pk_test_|sk_live_|sk_test_)[a-zA-Z0-9]{20,}\b'),
     "api_key", "[API KEY REDACTED]"),
]

# System prompt leakage indicators
LEAKAGE_PATTERNS = [
    re.compile(r'(my\s+(system\s+)?prompt\s+is|my\s+system\s+instructions\s+are)\s*[:=]?\s*.{10,}', re.IGNORECASE),
    re.compile(r'(here\s+(is|are)\s+my\s+(initial|secret|original)\s+(prompt|instructions?))', re.IGNORECASE),
    re.compile(r'(I\s+was\s+configured\s+with\s+the\s+following\s+system\s+prompt)', re.IGNORECASE),
]

# Unsafe content indicators
UNSAFE_PATTERNS = [
    (re.compile(r'\b(how\s+to\s+hack|exploit\s+vulnerability|bypass\s+authentication)\b', re.IGNORECASE), "security_risk"),
    (re.compile(r'\b(here\s+is\s+(the|a)\s+)?(malware|virus|trojan|ransomware)\s+(code|script|program)\b', re.IGNORECASE), "malware"),
]


class OutputAnalyzer:
    """Scans LLM output for sensitive data, prompt leakage, and unsafe content."""

    async def analyze(self, text: str) -> OutputAnalysisResult:
        start = time.perf_counter()

        if not text:
            return OutputAnalysisResult(safe=True, latency_ms=0.0)

        findings: List[Dict[str, Any]] = []
        sanitized = text
        max_score = 0.0

        # Check for sensitive data
        for pattern, data_type, replacement in SENSITIVE_PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                findings.append({
                    "type": "sensitive_data",
                    "data_type": data_type,
                    "count": len(matches),
                    "action": "redacted",
                })
                sanitized = pattern.sub(replacement, sanitized)
                max_score = max(max_score, 0.7)

        # Check for prompt leakage
        for pattern in LEAKAGE_PATTERNS:
            if pattern.search(sanitized):
                findings.append({
                    "type": "prompt_leakage",
                    "action": "flagged",
                })
                max_score = max(max_score, 0.8)

        # Check for unsafe content
        for pattern, risk_type in UNSAFE_PATTERNS:
            if pattern.search(sanitized):
                findings.append({
                    "type": "unsafe_content",
                    "risk_type": risk_type,
                    "action": "flagged",
                })
                max_score = max(max_score, 0.6)

        safe = max_score < 0.5
        latency = (time.perf_counter() - start) * 1000

        return OutputAnalysisResult(
            safe=safe,
            sanitized_text=sanitized if sanitized != text else None,
            findings=findings,
            score=round(max_score, 4),
            latency_ms=round(latency, 2),
        )
