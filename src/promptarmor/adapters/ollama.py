"""Adapter for a local Ollama server (http://localhost:11434 by default)."""

from __future__ import annotations

import requests

from promptarmor.adapters.base import Adapter, AdapterError


class OllamaAdapter(Adapter):
    """Talks to Ollama's /api/chat endpoint, non-streaming."""

    def send(self, prompt: str, system: str = "") -> str:
        url = f"{self.config.base_url}/api/chat"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
        }
        if self.config.options:
            payload["options"] = dict(self.config.options)

        try:
            response = requests.post(url, json=payload, timeout=self.config.timeout)
        except requests.ConnectionError as exc:
            raise AdapterError(
                f"Cannot reach Ollama at {self.config.base_url}. "
                "Is 'ollama serve' running?"
            ) from exc
        except requests.Timeout as exc:
            raise AdapterError(
                f"Ollama timed out after {self.config.timeout}s on model "
                f"'{self.config.model}'."
            ) from exc

        if response.status_code == 404:
            raise AdapterError(
                f"Model '{self.config.model}' not found on Ollama. "
                f"Try: ollama pull {self.config.model}"
            )
        if response.status_code != 200:
            raise AdapterError(
                f"Ollama returned HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            data = response.json()
            return str(data["message"]["content"])
        except (ValueError, KeyError, TypeError) as exc:
            raise AdapterError(
                f"Unexpected Ollama response shape: {response.text[:300]}"
            ) from exc
