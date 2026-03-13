"""Tests for LLM provider abstraction."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from binaryvibes.llm.provider import (
    AnthropicProvider,
    LLMError,
    LLMResponse,
    OpenAIProvider,
    create_provider,
)


class TestLLMResponse:
    def test_frozen(self):
        r = LLMResponse(content="hello", model="gpt-4o")
        with pytest.raises(AttributeError):
            r.content = "bye"

    def test_optional_usage(self):
        r = LLMResponse(content="hello", model="gpt-4o")
        assert r.usage is None

    def test_with_usage(self):
        r = LLMResponse(content="hello", model="gpt-4o", usage={"tokens": 10})
        assert r.usage == {"tokens": 10}


class TestOpenAIProvider:
    def test_init_defaults(self):
        p = OpenAIProvider(api_key="test-key")
        assert p.model == "gpt-4o"
        assert p.base_url == "https://api.openai.com/v1"

    def test_init_custom(self):
        p = OpenAIProvider(
            api_key="k", model="gpt-3.5", base_url="http://localhost:11434/v1/"
        )
        assert p.model == "gpt-3.5"
        assert p.base_url == "http://localhost:11434/v1"  # trailing slash stripped

    def test_complete_success(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "hello world"}}],
            "model": "gpt-4o",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            p = OpenAIProvider(api_key="test-key")
            result = p.complete([{"role": "user", "content": "hi"}])

        assert result.content == "hello world"
        assert result.model == "gpt-4o"
        assert result.usage is not None

    def test_complete_http_error(self):
        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_resp.text = "rate limited"
            mock_client.post.return_value = mock_resp
            mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
                "429", request=MagicMock(), response=mock_resp
            )
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            p = OpenAIProvider(api_key="test-key")
            with pytest.raises(LLMError, match="429"):
                p.complete([{"role": "user", "content": "hi"}])

    def test_complete_request_error(self):
        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.side_effect = httpx.RequestError("connection refused")
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            p = OpenAIProvider(api_key="test-key")
            with pytest.raises(LLMError, match="connection refused"):
                p.complete([{"role": "user", "content": "hi"}])

    def test_complete_malformed_response(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {"unexpected": "format"}
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            p = OpenAIProvider(api_key="test-key")
            with pytest.raises(LLMError, match="Unexpected response"):
                p.complete([{"role": "user", "content": "hi"}])


class TestAnthropicProvider:
    def test_init_defaults(self):
        p = AnthropicProvider(api_key="test-key")
        assert p.model == "claude-sonnet-4-20250514"
        assert p.max_tokens == 4096

    def test_complete_success(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "content": [{"text": "hello from claude"}],
            "model": "claude-sonnet-4-20250514",
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            p = AnthropicProvider(api_key="test-key")
            result = p.complete([
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "hi"},
            ])

        assert result.content == "hello from claude"
        # Verify system message was extracted
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        assert payload["system"] == "You are helpful"
        assert all(m["role"] != "system" for m in payload["messages"])

    def test_complete_no_system_message(self):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "content": [{"text": "response"}],
            "model": "claude-sonnet-4-20250514",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            p = AnthropicProvider(api_key="test-key")
            result = p.complete([{"role": "user", "content": "hi"}])

        assert result.content == "response"
        call_args = mock_client.post.call_args
        payload = call_args.kwargs.get("json") or call_args[1].get("json")
        assert "system" not in payload


class TestCreateProvider:
    def test_default_openai(self, monkeypatch):
        monkeypatch.setenv("BV_LLM_API_KEY", "test-key")
        monkeypatch.delenv("BV_LLM_PROVIDER", raising=False)
        p = create_provider()
        assert isinstance(p, OpenAIProvider)

    def test_anthropic_from_env(self, monkeypatch):
        monkeypatch.setenv("BV_LLM_API_KEY", "test-key")
        monkeypatch.setenv("BV_LLM_PROVIDER", "anthropic")
        p = create_provider()
        assert isinstance(p, AnthropicProvider)

    def test_explicit_args_override_env(self, monkeypatch):
        monkeypatch.setenv("BV_LLM_API_KEY", "env-key")
        monkeypatch.setenv("BV_LLM_PROVIDER", "anthropic")
        p = create_provider(provider="openai", api_key="explicit-key")
        assert isinstance(p, OpenAIProvider)
        assert p.api_key == "explicit-key"

    def test_missing_api_key(self, monkeypatch):
        monkeypatch.delenv("BV_LLM_API_KEY", raising=False)
        with pytest.raises(LLMError, match="No API key"):
            create_provider()

    def test_custom_model_from_env(self, monkeypatch):
        monkeypatch.setenv("BV_LLM_API_KEY", "test-key")
        monkeypatch.setenv("BV_LLM_MODEL", "gpt-3.5-turbo")
        p = create_provider()
        assert isinstance(p, OpenAIProvider)
        assert p.model == "gpt-3.5-turbo"

    def test_custom_base_url(self, monkeypatch):
        monkeypatch.setenv("BV_LLM_API_KEY", "test-key")
        monkeypatch.setenv("BV_LLM_BASE_URL", "http://localhost:11434/v1")
        p = create_provider()
        assert isinstance(p, OpenAIProvider)
        assert "localhost" in p.base_url
