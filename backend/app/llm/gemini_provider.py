"""
GeminiProvider — Google Gemini API integration via google-genai SDK.
Model name comes from GEMINI_MODEL env var (never hard-coded).
API key loaded server-side only, never exposed to frontend.
"""

import time
from google import genai
from google.genai import types
from app.llm.base import LLMProvider, LLMResponse
from app.config import settings


class GeminiProvider(LLMProvider):
    """Concrete LLM provider using Google Gemini API."""

    def __init__(self):
        self._model = settings.GEMINI_MODEL
        if settings.GEMINI_API_KEY:
            self._client = genai.Client(api_key=settings.GEMINI_API_KEY)
        else:
            self._client = None

    async def generate(self, prompt: str, system_instruction: str | None = None) -> LLMResponse:
        """Call Gemini API and return structured response."""
        if not self._client:
            from app.config import Settings
            current_settings = Settings()
            if current_settings.GEMINI_API_KEY:
                self._client = genai.Client(api_key=current_settings.GEMINI_API_KEY)
                self._model = current_settings.GEMINI_MODEL
        if not self._client:
            return LLMResponse(
                text="",
                model=self._model,
                latency_ms=0.0,
                error="Gemini integration requires configuration: GEMINI_API_KEY is not set in environment.",
            )
        start = time.perf_counter()
        try:
            config = None
            if system_instruction:
                config = types.GenerateContentConfig(
                    system_instruction=system_instruction,
                )

            models_to_try = [self._model]
            alt_model = "gemini-3.6-flash" if "3.5" in self._model else "gemini-3.5-flash"
            if alt_model not in models_to_try:
                models_to_try.append(alt_model)

            response = None
            used_model = self._model
            for m in models_to_try:
                try:
                    response = self._client.models.generate_content(
                        model=m,
                        contents=prompt,
                        config=config,
                    )
                    used_model = m
                    break
                except Exception as ex:
                    if ("503" in str(ex) or "404" in str(ex)) and m != models_to_try[-1]:
                        continue
                    raise

            latency = (time.perf_counter() - start) * 1000
            text = response.text if response and response.text else ""

            return LLMResponse(
                text=text,
                model=used_model,
                latency_ms=round(latency, 2),
                token_count=None,
            )
        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            return LLMResponse(
                text="",
                model=self._model,
                latency_ms=round(latency, 2),
                error=str(e),
            )

    async def health_check(self) -> bool:
        """Quick connectivity check to Gemini API."""
        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents="Say OK",
            )
            return bool(response.text)
        except Exception:
            return False


# Singleton instance
_provider: GeminiProvider | None = None


def get_gemini_provider() -> GeminiProvider:
    global _provider
    if _provider is None:
        _provider = GeminiProvider()
    return _provider
