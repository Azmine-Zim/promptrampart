"""Target adapters: one class per way of talking to a model."""

from __future__ import annotations

from promptarmor.adapters.base import Adapter, AdapterError
from promptarmor.adapters.mock import MockAdapter
from promptarmor.adapters.ollama import OllamaAdapter
from promptarmor.config import TargetConfig

_REGISTRY: dict[str, type[Adapter]] = {
    "ollama": OllamaAdapter,
    "mock": MockAdapter,
}


def build_adapter(config: TargetConfig) -> Adapter:
    """Create the adapter instance named in the target config."""
    try:
        adapter_cls = _REGISTRY[config.adapter]
    except KeyError:
        raise AdapterError(
            f"Adapter '{config.adapter}' is not implemented yet. "
            f"Available: {', '.join(sorted(_REGISTRY))}"
        ) from None
    return adapter_cls(config)


__all__ = ["Adapter", "AdapterError", "OllamaAdapter", "MockAdapter", "build_adapter"]
