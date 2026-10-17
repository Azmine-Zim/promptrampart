"""Adapter for OpenAI-compatible chat completion APIs.

Works with the official OpenAI API and any server that speaks the same
protocol (LM Studio, vLLM, llama.cpp server, OpenRouter, and so on).
The API key is never stored in config files; it is read from the
environment variable named by 'api_key_env'.
"""

from __future__ import annotations

import requests

from promptrampart.adapters.base import Adapter, AdapterError


class OpenAIAdapter(Adapter):
    """Talks to a /v1/chat/completions endpoint, non-streaming."""

    def send(self, prompt: str, system: str = "") -> str:
        if not self.config.base_url:
            raise AdapterError(
                "openai adapter needs a 'base_url' (e.g. https://api.openai.com/v1)."
            )

        url = f"{self.config.base_url}/chat/completions"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict = {"model": self.config.model, "messages": messages}
        payload.update(self.config.options)

        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        try:
            response = requests.post(
                url, json=payload, headers=headers, timeout=self.config.timeout
            )
        except requests.ConnectionError as exc:
            raise AdapterError(f"Cannot reach API at {self.config.base_url}.") from exc
        except requests.Timeout as exc:
            raise AdapterError(
                f"API timed out after {self.config.timeout}s on model "
                f"'{self.config.model}'."
            ) from exc

        if response.status_code == 401:
            raise AdapterError(
                "API returned 401 Unauthorized. Check the environment variable "
                "named in 'api_key_env'."
            )
        if response.status_code != 200:
            raise AdapterError(
                f"API returned HTTP {response.status_code}: {response.text[:300]}"
            )

        try:
            data = response.json()
            return str(data["choices"][0]["message"]["content"])
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AdapterError(
                f"Unexpected API response shape: {response.text[:300]}"
            ) from exc
