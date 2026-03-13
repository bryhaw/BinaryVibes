"""LLM provider abstraction for BinaryVibes."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx


class LLMError(Exception):
    """Raised when LLM interaction fails."""


@dataclass(frozen=True)
class LLMResponse:
    """Response from an LLM provider."""

    content: str
    model: str
    usage: dict | None = None


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def complete(
        self, messages: list[dict[str, str]], temperature: float = 0.0
    ) -> LLMResponse:
        """Send messages to the LLM and return the response.

        Args:
            messages: List of {"role": "system"|"user"|"assistant", "content": "..."} dicts.
            temperature: Sampling temperature (0.0 = deterministic).

        Returns:
            LLMResponse with the model's text output.

        Raises:
            LLMError: If the request fails.
        """
        ...


class OpenAIProvider(LLMProvider):
    """Provider for OpenAI-compatible APIs (OpenAI, Azure, Ollama, vLLM, Together, Groq, etc.)."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 120.0,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def complete(
        self, messages: list[dict[str, str]], temperature: float = 0.0
    ) -> LLMResponse:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            raise LLMError(
                f"LLM request failed ({e.response.status_code}): {e.response.text}"
            ) from e
        except httpx.RequestError as e:
            raise LLMError(f"LLM request error: {e}") from e

        try:
            content = data["choices"][0]["message"]["content"]
            model = data.get("model", self.model)
            usage = data.get("usage")
            return LLMResponse(content=content, model=model, usage=usage)
        except (KeyError, IndexError) as e:
            raise LLMError(f"Unexpected response format: {data}") from e


class AnthropicProvider(LLMProvider):
    """Provider for Anthropic's Messages API."""

    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        timeout: float = 120.0,
    ):
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout

    def complete(
        self, messages: list[dict[str, str]], temperature: float = 0.0
    ) -> LLMResponse:
        # Anthropic separates system message from the messages list
        system = None
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                chat_messages.append(msg)

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload: dict = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": chat_messages,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(self.API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            raise LLMError(
                f"Anthropic request failed ({e.response.status_code}): "
                f"{e.response.text}"
            ) from e
        except httpx.RequestError as e:
            raise LLMError(f"Anthropic request error: {e}") from e

        try:
            content = data["content"][0]["text"]
            model = data.get("model", self.model)
            usage = data.get("usage")
            return LLMResponse(content=content, model=model, usage=usage)
        except (KeyError, IndexError) as e:
            raise LLMError(f"Unexpected Anthropic response format: {data}") from e


def create_provider(
    provider: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> LLMProvider:
    """Create an LLM provider from explicit args or environment variables.

    Environment variables (used as fallbacks):
        BV_LLM_PROVIDER: "openai" or "anthropic" (default: "openai")
        BV_LLM_API_KEY: API key for the provider
        BV_LLM_MODEL: Model name
        BV_LLM_BASE_URL: Base URL (OpenAI-compatible providers only)

    Raises:
        LLMError: If required configuration is missing.
    """
    provider = provider or os.environ.get("BV_LLM_PROVIDER", "openai")
    api_key = api_key or os.environ.get("BV_LLM_API_KEY", "")

    if not api_key:
        raise LLMError(
            "No API key provided. Set BV_LLM_API_KEY environment variable "
            "or pass --api-key to the command."
        )

    if provider == "anthropic":
        model = model or os.environ.get("BV_LLM_MODEL", "claude-sonnet-4-20250514")
        return AnthropicProvider(api_key=api_key, model=model)
    else:
        model = model or os.environ.get("BV_LLM_MODEL", "gpt-4o")
        base_url = base_url or os.environ.get(
            "BV_LLM_BASE_URL", "https://api.openai.com/v1"
        )
        return OpenAIProvider(api_key=api_key, model=model, base_url=base_url)
