"""Target configuration loading and validation.

A target config is a small YAML file that tells PromptArmor which model to
attack and how to reach it. Example (Ollama):

    adapter: ollama
    model: llama3.2:1b
    base_url: http://localhost:11434
    options:
      temperature: 0.0

Example (OpenAI-compatible, planned for M3):

    adapter: openai
    model: gpt-4o-mini
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_ADAPTERS = ("ollama", "openai", "mock")


class ConfigError(Exception):
    """Raised when a target config file is missing or invalid."""


@dataclass
class TargetConfig:
    """Validated settings for one attack target."""

    adapter: str
    model: str
    base_url: str = ""
    api_key: str = ""
    timeout: float = 120.0
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.adapter}:{self.model}"


def load_target_config(path: str | Path) -> TargetConfig:
    """Load and validate a YAML target config file."""
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"Config file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping, got {type(raw).__name__}")

    adapter = str(raw.get("adapter", "")).strip().lower()
    if adapter not in SUPPORTED_ADAPTERS:
        raise ConfigError(
            f"Unknown adapter '{adapter}'. Supported: {', '.join(SUPPORTED_ADAPTERS)}"
        )

    model = str(raw.get("model", "")).strip()
    if not model:
        raise ConfigError("Config must set a non-empty 'model'.")

    base_url = str(raw.get("base_url", "")).strip().rstrip("/")
    if adapter == "ollama" and not base_url:
        base_url = "http://localhost:11434"

    api_key = ""
    api_key_env = str(raw.get("api_key_env", "")).strip()
    if api_key_env:
        api_key = os.environ.get(api_key_env, "")

    timeout = float(raw.get("timeout", 120.0))
    if timeout <= 0:
        raise ConfigError("'timeout' must be a positive number of seconds.")

    options = raw.get("options") or {}
    if not isinstance(options, dict):
        raise ConfigError("'options' must be a mapping if present.")

    return TargetConfig(
        adapter=adapter,
        model=model,
        base_url=base_url,
        api_key=api_key,
        timeout=timeout,
        options=options,
    )
