"""
Abstract LLM provider interface.
All model interaction goes through this abstraction —
the security framework is model-provider independent.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class LLMResponse:
    text: str
    model: str
    latency_ms: float
    token_count: Optional[int] = None
    error: Optional[str] = None


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(self, prompt: str, system_instruction: str | None = None) -> LLMResponse:
        """Generate a response from the LLM."""
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify connectivity to the LLM service."""
        ...
