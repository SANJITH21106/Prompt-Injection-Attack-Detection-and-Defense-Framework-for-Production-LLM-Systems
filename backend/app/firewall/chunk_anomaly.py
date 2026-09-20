"""
Layer 5: Chunk Anomaly Analysis
Splits content into semantic chunks and analyzes each for anomalous patterns
vs. surrounding context. Detects malicious instructions hidden within benign content.
Classified as weak_anomaly evidence unless very strong signal.
"""

import re
import time
from typing import Any, Dict, List, Optional
from app.firewall.base_layer import SecurityLayer, LayerResult

# Indicators of malicious content in a chunk
MALICIOUS_INDICATORS = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)", re.IGNORECASE), "instruction_override", 0.85),
    (re.compile(r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be)", re.IGNORECASE), "role_manipulation", 0.7),
    (re.compile(r"(reveal|show|output|print)\s+(your|the)\s+(system|initial)", re.IGNORECASE), "prompt_extraction", 0.8),
    (re.compile(r"(bypass|disable|override)\s+(safety|filter|security|restriction)", re.IGNORECASE), "safety_bypass", 0.85),
    (re.compile(r"(SELECT|DROP|DELETE|INSERT|UPDATE|TRUNCATE)\s+", re.IGNORECASE), "sql_content", 0.6),
    (re.compile(r"<\s*(system|admin|instruction|ignore)\s*>", re.IGNORECASE), "xml_injection", 0.75),
    (re.compile(r"\[SYSTEM\]|\[INST\]|\[ADMIN\]", re.IGNORECASE), "delimiter_injection", 0.8),
]


class ChunkAnomalyLayer(SecurityLayer):
    """Layer 5: Chunk Anomaly Analysis — detects hidden malicious content in chunks."""

    @property
    def name(self) -> str:
        return "Chunk Anomaly Analysis"

    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        start = time.perf_counter()

        # Split into semantic chunks (paragraphs, code blocks, delimited sections)
        chunks = self._split_chunks(content)
        suspicious_chunks: List[Dict[str, Any]] = []
        max_chunk_score = 0.0

        for i, chunk in enumerate(chunks):
            chunk_findings = []
            chunk_max = 0.0

            for pattern_re, category, weight in MALICIOUS_INDICATORS:
                if pattern_re.search(chunk):
                    chunk_findings.append({"category": category, "weight": weight})
                    chunk_max = max(chunk_max, weight)

            # Context anomaly: is this chunk significantly different from neighbors?
            context_score = self._context_anomaly_score(chunk, chunks, i)

            if chunk_findings or context_score > 0.5:
                combined = max(chunk_max, context_score * 0.7)
                suspicious_chunks.append({
                    "chunk_index": i,
                    "chunk_preview": chunk[:80],
                    "findings": chunk_findings,
                    "pattern_score": round(chunk_max, 4),
                    "context_anomaly_score": round(context_score, 4),
                    "combined_score": round(combined, 4),
                })
                max_chunk_score = max(max_chunk_score, combined)

        # Score: if there are benign chunks alongside suspicious ones, that's the anomaly
        if suspicious_chunks:
            benign_ratio = 1 - (len(suspicious_chunks) / max(len(chunks), 1))
            # Higher anomaly when few chunks are suspicious within mostly-benign content
            if benign_ratio > 0.5:
                anomaly_boost = min(0.1, benign_ratio * 0.1)
            else:
                anomaly_boost = 0.0
            score = min(1.0, max_chunk_score + anomaly_boost)
        else:
            score = 0.0

        passed = score < 0.5
        latency = (time.perf_counter() - start) * 1000

        # Chunk anomaly is generally weak evidence unless very strong malicious patterns
        if max_chunk_score >= 0.85 and len(suspicious_chunks) >= 2:
            evidence_type = "strong_semantic"
        else:
            evidence_type = "weak_anomaly"

        return LayerResult(
            layer_name=self.name,
            passed=passed,
            score=round(score, 4),
            details={
                "total_chunks": len(chunks),
                "suspicious_chunks": len(suspicious_chunks),
                "suspicious_details": suspicious_chunks[:5],  # Limit detail size
                "reason": f"Found {len(suspicious_chunks)} suspicious chunk(s) out of {len(chunks)} total."
                          if suspicious_chunks else "No chunk-level anomalies detected.",
            },
            latency_ms=round(latency, 2),
            evidence_type=evidence_type,
            hard_block_trigger=False,  # Chunk anomaly alone never hard-blocks
        )

    def _split_chunks(self, content: str) -> List[str]:
        """Split content into semantic chunks."""
        # Split on double newlines, XML-like tags, markdown headers, code blocks
        raw_chunks = re.split(r'\n\n+|(?=<[^/])|(?=```)|(?=#{1,3}\s)', content)
        # Filter out empty chunks and strip
        return [c.strip() for c in raw_chunks if c.strip() and len(c.strip()) > 5]

    def _context_anomaly_score(self, chunk: str, all_chunks: List[str], index: int) -> float:
        """Measure how anomalous this chunk is compared to its neighbors."""
        if len(all_chunks) <= 1:
            return 0.0

        chunk_lower = chunk.lower()
        neighbors = []
        if index > 0:
            neighbors.append(all_chunks[index - 1].lower())
        if index < len(all_chunks) - 1:
            neighbors.append(all_chunks[index + 1].lower())

        if not neighbors:
            return 0.0

        # Simple vocabulary overlap check
        chunk_words = set(re.findall(r'\w+', chunk_lower))
        if not chunk_words:
            return 0.0

        neighbor_words = set()
        for n in neighbors:
            neighbor_words.update(re.findall(r'\w+', n))

        if not neighbor_words:
            return 0.0

        overlap = len(chunk_words & neighbor_words) / max(len(chunk_words), 1)

        # Low overlap = high anomaly, but only matters if the chunk has suspicious traits
        anomaly = max(0.0, 1.0 - overlap * 2)
        return min(1.0, anomaly)
