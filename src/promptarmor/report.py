"""JSON export of assessment results.

The JSON schema is stable and versioned so downstream tooling (and the
upcoming HTML report card in M3) can rely on it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from promptarmor import __version__
from promptarmor.pack import VALID_SEVERITIES
from promptarmor.runner import RunResult

SCHEMA_VERSION = 1


def run_to_dict(run: RunResult) -> dict:
    """Serialize a RunResult into a plain JSON-safe dict."""
    scored = run.passed + run.failed
    resistance_rate = round(run.passed / scored * 100, 1) if scored else 0.0

    breached_by_severity = {severity: 0 for severity in VALID_SEVERITIES}
    for result in run.results:
        if result.verdict == "FAIL":
            breached_by_severity[result.attack.severity] += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "promptarmor", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": run.target_label,
        "pack": run.pack_name,
        "canary": run.canary,
        "summary": {
            "attacks_run": len(run.results),
            "resisted": run.passed,
            "breached": run.failed,
            "errors": run.errored,
            "resistance_rate_pct": resistance_rate,
            "breached_by_severity": breached_by_severity,
            "by_category": run.by_category(),
        },
        "results": [
            {
                "id": result.attack.id,
                "category": result.attack.category,
                "owasp": result.attack.owasp,
                "severity": result.attack.severity,
                "title": result.attack.title,
                "prompt": result.attack.prompt,
                "verdict": result.verdict,
                "response": result.response,
                "duration_s": round(result.duration_s, 3),
                "error": result.error,
                "detections": [
                    {
                        "type": detection.detector_type,
                        "fired": detection.fired,
                        "detail": detection.detail,
                    }
                    for detection in result.detections
                ],
            }
            for result in run.results
        ],
    }


def write_json(run: RunResult, path: str | Path) -> Path:
    """Write the run results as pretty-printed JSON. Returns the path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(run_to_dict(run), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path
