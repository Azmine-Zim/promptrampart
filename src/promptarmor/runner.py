"""Orchestrates one assessment run: pack x target -> results."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from promptarmor.adapters import build_adapter
from promptarmor.adapters.base import AdapterError
from promptarmor.config import TargetConfig
from promptarmor.pack import Attack, AttackPack
from promptarmor.scoring import CANARY_PLACEHOLDER, Detection, evaluate, make_canary


@dataclass
class AttackResult:
    """Outcome of one attack prompt against the target."""

    attack: Attack
    response: str
    attack_succeeded: bool  # True means the model FAILED this test
    detections: list[Detection]
    duration_s: float
    error: str = ""

    @property
    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        return "FAIL" if self.attack_succeeded else "PASS"


@dataclass
class RunResult:
    """Everything produced by one full assessment run."""

    target_label: str
    pack_name: str
    canary: str
    results: list[AttackResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.verdict == "PASS")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.verdict == "FAIL")

    @property
    def errored(self) -> int:
        return sum(1 for r in self.results if r.verdict == "ERROR")

    def by_category(self) -> dict[str, dict[str, int]]:
        """Per-category pass/fail/error counts."""
        stats: dict[str, dict[str, int]] = {}
        for result in self.results:
            bucket = stats.setdefault(
                result.attack.category, {"PASS": 0, "FAIL": 0, "ERROR": 0}
            )
            bucket[result.verdict] += 1
        return stats


def run_pack(
    config: TargetConfig,
    pack: AttackPack,
    on_result=None,
) -> RunResult:
    """Run every attack in the pack against the target.

    on_result, if given, is called with each AttackResult as it completes,
    so the CLI can stream progress to the console.
    """
    adapter = build_adapter(config)
    canary = make_canary()
    system_prompt = pack.default_system_prompt.replace(CANARY_PLACEHOLDER, canary)

    run = RunResult(target_label=config.label, pack_name=pack.name, canary=canary)

    for attack in pack.attacks:
        started = time.monotonic()
        response = ""
        error = ""
        attack_succeeded = False
        detections: list[Detection] = []
        try:
            response = adapter.send(attack.prompt, system=system_prompt)
            attack_succeeded, detections = evaluate(
                attack.detectors, response, canary=canary
            )
        except AdapterError as exc:
            error = str(exc)
        duration = time.monotonic() - started

        result = AttackResult(
            attack=attack,
            response=response,
            attack_succeeded=attack_succeeded,
            detections=detections,
            duration_s=duration,
            error=error,
        )
        run.results.append(result)
        if on_result is not None:
            on_result(result)

    return run
