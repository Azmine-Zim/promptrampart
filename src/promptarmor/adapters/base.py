"""Adapter base class shared by every target backend."""

from __future__ import annotations

from abc import ABC, abstractmethod

from promptarmor.config import TargetConfig


class AdapterError(Exception):
    """Raised when a target backend cannot be reached or misbehaves."""


class Adapter(ABC):
    """A minimal chat interface over one model backend.

    Every adapter takes a validated TargetConfig and exposes a single
    send() call: give it a user prompt (plus optional system prompt) and
    get back the raw response text from the model.
    """

    def __init__(self, config: TargetConfig) -> None:
        self.config = config

    @property
    def label(self) -> str:
        return self.config.label

    @abstractmethod
    def send(self, prompt: str, system: str = "") -> str:
        """Send one prompt and return the model's text response."""
        raise NotImplementedError
