"""
Layer 2: SQL & Intent Check
Uses sqlglot to parse SQL-like content and detect injection attacks.
Deterministic: destructive SQL (DROP/DELETE/TRUNCATE) triggers hard_block.
"""

import re
import time
from typing import Any, Dict, Optional
from app.firewall.base_layer import SecurityLayer, LayerResult

try:
    import sqlglot
    from sqlglot import errors as sqlglot_errors
    HAS_SQLGLOT = True
except ImportError:
    HAS_SQLGLOT = False

# Regex patterns for SQL content detection
SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|UNION|EXEC|EXECUTE|GRANT|REVOKE|"
    r"WHERE|FROM|JOIN|INTO|VALUES|SET|TABLE|DATABASE|SCHEMA|INDEX|VIEW|PROCEDURE|FUNCTION|TRIGGER)\b",
    re.IGNORECASE
)

# Destructive SQL operations — these trigger hard_block
DESTRUCTIVE_OPS = {"DROP", "DELETE", "TRUNCATE", "ALTER", "EXEC", "EXECUTE", "GRANT", "REVOKE"}

# SQL injection patterns
INJECTION_PATTERNS = [
    (re.compile(r"['\"]\s*(OR|AND)\s+['\"0-9]\s*=\s*['\"0-9]", re.IGNORECASE), "tautology", 0.9),
    (re.compile(r";\s*(DROP|DELETE|TRUNCATE|ALTER|INSERT|UPDATE)\b", re.IGNORECASE), "stacked_query", 0.95),
    (re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.IGNORECASE), "union_injection", 0.9),
    (re.compile(r"--\s*$|/\*.*\*/", re.IGNORECASE), "comment_injection", 0.5),
    (re.compile(r"\binformation_schema\b|\bsys\.\b|\bsysobjects\b|\bpg_catalog\b", re.IGNORECASE), "system_table_access", 0.85),
    (re.compile(r"1\s*=\s*1|'1'\s*=\s*'1'|1\s*=\s*'1'", re.IGNORECASE), "tautology_literal", 0.85),
    (re.compile(r"\bWAITFOR\s+DELAY\b|\bSLEEP\s*\(", re.IGNORECASE), "time_based_injection", 0.9),
    (re.compile(r"\bBENCHMARK\s*\(", re.IGNORECASE), "benchmark_injection", 0.85),
    (re.compile(r"\bLOAD_FILE\s*\(|\bINTO\s+(OUT|DUMP)FILE\b", re.IGNORECASE), "file_access", 0.95),
]


class SQLIntentLayer(SecurityLayer):
    """Layer 2: SQL & Intent Analysis — sqlglot parsing + injection detection."""

    @property
    def name(self) -> str:
        return "SQL & Intent Analysis"

    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        start = time.perf_counter()
        findings = []
        max_score = 0.0
        has_destructive = False
        parsed_statements = []

        # Check for SQL keywords first
        sql_keywords_found = SQL_KEYWORDS_RE.findall(content)
        if not sql_keywords_found:
            latency = (time.perf_counter() - start) * 1000
            return LayerResult(
                layer_name=self.name,
                passed=True,
                score=0.0,
                details={"reason": "No SQL content detected.", "findings": []},
                latency_ms=round(latency, 2),
                evidence_type="weak_anomaly",
                hard_block_trigger=False,
            )

        # Try sqlglot parsing
        if HAS_SQLGLOT:
            try:
                statements = sqlglot.parse(content, error_level=sqlglot_errors.ErrorLevel.IGNORE)
                for stmt in statements:
                    if stmt is not None:
                        stmt_type = type(stmt).__name__
                        parsed_statements.append(stmt_type)
                        # Check for destructive operations
                        if any(op.lower() in stmt.sql().lower() for op in DESTRUCTIVE_OPS):
                            has_destructive = True
                            findings.append({
                                "type": "destructive_sql",
                                "statement": stmt.sql()[:100],
                                "severity": "critical",
                            })
                            max_score = max(max_score, 0.95)
            except Exception:
                pass  # sqlglot parse failure — fall through to regex

        # Check injection patterns
        for pattern_re, pattern_name, weight in INJECTION_PATTERNS:
            matches = pattern_re.findall(content)
            if matches:
                findings.append({
                    "type": pattern_name,
                    "match_count": len(matches),
                    "severity": "critical" if weight >= 0.9 else "high" if weight >= 0.7 else "medium",
                })
                max_score = max(max_score, weight)
                if pattern_name in ("stacked_query", "file_access"):
                    has_destructive = True

        # Check for destructive keyword presence
        upper_content = content.upper()
        for op in DESTRUCTIVE_OPS:
            if op in upper_content:
                if re.search(rf"\b{op}\b", content, re.IGNORECASE):
                    has_destructive = True
                    if not any(f["type"] == "destructive_sql" for f in findings):
                        findings.append({
                            "type": "destructive_keyword",
                            "keyword": op,
                            "severity": "critical",
                        })
                        max_score = max(max_score, 0.9)

        score = min(1.0, max_score)
        passed = score < 0.5
        latency = (time.perf_counter() - start) * 1000

        # Evidence classification
        if has_destructive:
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
                "findings": findings,
                "sql_keywords_found": list(set(sql_keywords_found)),
                "parsed_statements": parsed_statements,
                "has_destructive_sql": has_destructive,
                "reason": f"Detected {len(findings)} SQL security issue(s). "
                          f"Destructive SQL: {'YES' if has_destructive else 'NO'}."
                          if findings else "SQL content found but no injection patterns detected.",
            },
            latency_ms=round(latency, 2),
            evidence_type=evidence_type,
            hard_block_trigger=has_destructive,  # Destructive SQL = immediate BLOCK
        )
