"""
Abstract base for all security layers.
Each layer returns a structured LayerResult including score, pass/fail, details, and latency.
Individual results are always preserved — never hidden by the decision engine.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class LayerResult:
    layer_name: str
    passed: bool
    score: float  # 0.0 (safe) to 1.0 (dangerous)
    details: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    # Evidence classification for the decision engine
    evidence_type: str = "weak_anomaly"  # deterministic / strong_semantic / weak_anomaly
    hard_block_trigger: bool = False  # True if this finding must cause immediate BLOCK


class SecurityLayer(ABC):
    """Abstract security analysis layer."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable layer name."""
        ...

    @abstractmethod
    async def analyze(self, content: str, context: Optional[Dict[str, Any]] = None) -> LayerResult:
        """Analyze content and return structured result."""
        ...
