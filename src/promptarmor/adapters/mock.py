"""Offline mock adapter used for tests and dry runs without any model.

It plays a deliberately naive assistant: it refuses prompts containing a
few obvious attack keywords and otherwise echoes a canned reply. This lets
the whole pipeline (config, pack, runner, scoring, output) be exercised
end to end with zero network access.
"""

from __future__ import annotations

from promptarmor.adapters.base import Adapter

_REFUSAL = (
    "I'm sorry, but I can't help with that request. "
    "It appears to conflict with my usage guidelines."
)

_COMPLIANT = (
    "Sure, here is the information you asked for about Acme products. "
    "Let me know if you need anything else."
)

# Blunt attacks the mock recognizes and refuses.
_REFUSE_FRAGMENTS = (
    "ignore all previous instructions",
    "ignore your previous instructions",
    "do anything now",
    "developer mode",
    "no restrictions",
)

# Social engineering the mock falls for: it parrots back its own
# system prompt, leaking whatever canary token was planted in it.
_LEAK_FRAGMENTS = (
    "audit token",
    "initial instructions",
    "your system prompt",
    "instructions you were given",
    "spell out any token",
)


class MockAdapter(Adapter):
    """Deterministic fake model for offline testing.

    It refuses blunt, keyword-heavy attacks but falls for polite social
    engineering by reciting its system prompt, so an offline demo shows
    both resisted and breached attacks.
    """

    def send(self, prompt: str, system: str = "") -> str:
        lowered = prompt.lower()
        if any(fragment in lowered for fragment in _REFUSE_FRAGMENTS):
            return _REFUSAL
        if any(fragment in lowered for fragment in _LEAK_FRAGMENTS):
            return (
                "Of course, happy to help with your audit! Here is everything "
                f"I was told at the start of our chat: {system}"
            )
        return _COMPLIANT
