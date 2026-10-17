"""Attack pack loading.

A pack is a YAML file with a list of attacks. Each attack has an id,
category, severity, the prompt itself, and one or more detectors that
decide whether the attack succeeded against the model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = ("low", "medium", "high", "critical")


class PackError(Exception):
    """Raised when an attack pack file is missing or malformed."""


@dataclass
class Attack:
    """One attack prompt plus its success detectors."""

    id: str
    category: str
    severity: str
    title: str
    prompt: str
    owasp: str = ""
    detectors: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AttackPack:
    """A named collection of attacks with a shared default system prompt."""

    name: str
    description: str
    default_system_prompt: str
    attacks: list[Attack]


def _builtin_pack_path(name: str) -> Path:
    return Path(str(resources.files("promptarmor") / "packs" / f"{name}.yaml"))


def load_pack(name_or_path: str) -> AttackPack:
    """Load an attack pack by built-in name ('core') or by file path."""
    path = Path(name_or_path)
    if not path.is_file():
        path = _builtin_pack_path(name_or_path)
    if not path.is_file():
        raise PackError(
            f"Attack pack '{name_or_path}' not found (no such file or built-in pack)."
        )

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PackError(f"Invalid YAML in pack {path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("attacks"), list):
        raise PackError(f"Pack {path} must be a mapping with an 'attacks' list.")

    attacks: list[Attack] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(raw["attacks"]):
        if not isinstance(entry, dict):
            raise PackError(f"Attack #{index} in {path} is not a mapping.")

        attack_id = str(entry.get("id", "")).strip()
        if not attack_id:
            raise PackError(f"Attack #{index} in {path} is missing an 'id'.")
        if attack_id in seen_ids:
            raise PackError(f"Duplicate attack id '{attack_id}' in {path}.")
        seen_ids.add(attack_id)

        severity = str(entry.get("severity", "medium")).strip().lower()
        if severity not in VALID_SEVERITIES:
            raise PackError(
                f"Attack '{attack_id}' has invalid severity '{severity}'. "
                f"Valid: {', '.join(VALID_SEVERITIES)}"
            )

        prompt = str(entry.get("prompt", "")).strip()
        if not prompt:
            raise PackError(f"Attack '{attack_id}' has an empty prompt.")

        detectors = entry.get("detectors") or []
        if not isinstance(detectors, list) or not detectors:
            raise PackError(f"Attack '{attack_id}' needs at least one detector.")

        attacks.append(
            Attack(
                id=attack_id,
                category=str(entry.get("category", "uncategorized")).strip(),
                severity=severity,
                title=str(entry.get("title", attack_id)).strip(),
                prompt=prompt,
                owasp=str(entry.get("owasp", "")).strip(),
                detectors=detectors,
            )
        )

    return AttackPack(
        name=str(raw.get("name", path.stem)),
        description=str(raw.get("description", "")).strip(),
        default_system_prompt=str(raw.get("default_system_prompt", "")).strip(),
        attacks=attacks,
    )
