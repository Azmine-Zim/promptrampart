"""Tests for the OpenAI-compatible adapter (no real network calls)."""

import pytest

from promptrampart.adapters import build_adapter
from promptrampart.adapters.base import AdapterError
from promptrampart.adapters.openai import OpenAIAdapter
from promptrampart.config import TargetConfig


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or str(payload)

    def json(self):
        return self._payload


def openai_config(**overrides):
    defaults = dict(
        adapter="openai",
        model="test-model",
        base_url="https://api.example.com/v1",
        api_key="test-key-not-real",
        timeout=5,
    )
    defaults.update(overrides)
    return TargetConfig(**defaults)


def test_build_adapter_returns_openai_adapter():
    adapter = build_adapter(openai_config())
    assert isinstance(adapter, OpenAIAdapter)


def test_send_parses_choices(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured.update(url=url, json=json, headers=headers)
        return FakeResponse(
            payload={"choices": [{"message": {"content": "hello there"}}]}
        )

    monkeypatch.setattr("promptrampart.adapters.openai.requests.post", fake_post)
    adapter = OpenAIAdapter(openai_config())
    reply = adapter.send("hi", system="be nice")

    assert reply == "hello there"
    assert captured["url"] == "https://api.example.com/v1/chat/completions"
    assert captured["json"]["messages"][0] == {"role": "system", "content": "be nice"}
    assert captured["json"]["messages"][1] == {"role": "user", "content": "hi"}
    assert captured["headers"]["Authorization"] == "Bearer test-key-not-real"


def test_send_omits_auth_header_without_key(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured.update(headers=headers)
        return FakeResponse(payload={"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr("promptrampart.adapters.openai.requests.post", fake_post)
    adapter = OpenAIAdapter(openai_config(api_key=""))
    adapter.send("hi")
    assert "Authorization" not in captured["headers"]


def test_401_raises_helpful_error(monkeypatch):
    monkeypatch.setattr(
        "promptrampart.adapters.openai.requests.post",
        lambda *a, **k: FakeResponse(status_code=401, text="unauthorized"),
    )
    adapter = OpenAIAdapter(openai_config())
    with pytest.raises(AdapterError, match="401"):
        adapter.send("hi")


def test_bad_shape_raises(monkeypatch):
    monkeypatch.setattr(
        "promptrampart.adapters.openai.requests.post",
        lambda *a, **k: FakeResponse(payload={"unexpected": True}),
    )
    adapter = OpenAIAdapter(openai_config())
    with pytest.raises(AdapterError, match="response shape"):
        adapter.send("hi")


def test_missing_base_url_raises():
    adapter = OpenAIAdapter(openai_config(base_url=""))
    with pytest.raises(AdapterError, match="base_url"):
        adapter.send("hi")


def test_options_merged_into_payload(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured.update(json=json)
        return FakeResponse(payload={"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr("promptrampart.adapters.openai.requests.post", fake_post)
    adapter = OpenAIAdapter(openai_config(options={"temperature": 0.0}))
    adapter.send("hi")
    assert captured["json"]["temperature"] == 0.0
