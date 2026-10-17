"""Tests for target config loading and validation."""

import pytest

from promptrampart.config import ConfigError, load_target_config


def write_config(tmp_path, text):
    path = tmp_path / "target.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_ollama_config(tmp_path):
    path = write_config(
        tmp_path,
        "adapter: ollama\nmodel: llama3.2:1b\noptions:\n  temperature: 0.0\n",
    )
    config = load_target_config(path)
    assert config.adapter == "ollama"
    assert config.model == "llama3.2:1b"
    assert config.base_url == "http://localhost:11434"  # default filled in
    assert config.options == {"temperature": 0.0}
    assert config.label == "ollama:llama3.2:1b"


def test_base_url_trailing_slash_stripped(tmp_path):
    path = write_config(
        tmp_path,
        "adapter: ollama\nmodel: m\nbase_url: http://box:11434/\n",
    )
    assert load_target_config(path).base_url == "http://box:11434"


def test_api_key_read_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PA_TEST_KEY", "secret123")
    path = write_config(
        tmp_path,
        "adapter: openai\nmodel: gpt-x\nbase_url: https://api.example.com/v1\n"
        "api_key_env: PA_TEST_KEY\n",
    )
    assert load_target_config(path).api_key == "secret123"


def test_missing_file_raises():
    with pytest.raises(ConfigError, match="not found"):
        load_target_config("no/such/file.yaml")


def test_unknown_adapter_raises(tmp_path):
    path = write_config(tmp_path, "adapter: carrier_pigeon\nmodel: m\n")
    with pytest.raises(ConfigError, match="Unknown adapter"):
        load_target_config(path)


def test_missing_model_raises(tmp_path):
    path = write_config(tmp_path, "adapter: ollama\n")
    with pytest.raises(ConfigError, match="model"):
        load_target_config(path)


def test_bad_timeout_raises(tmp_path):
    path = write_config(tmp_path, "adapter: ollama\nmodel: m\ntimeout: -5\n")
    with pytest.raises(ConfigError, match="timeout"):
        load_target_config(path)


def test_non_mapping_root_raises(tmp_path):
    path = write_config(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_target_config(path)
