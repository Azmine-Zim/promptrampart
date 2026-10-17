"""Tests for the JSON results export."""

import json

from promptrampart.config import TargetConfig
from promptrampart.pack import load_pack
from promptrampart.report import SCHEMA_VERSION, run_to_dict, write_json
from promptrampart.runner import run_pack


def make_run():
    pack = load_pack("core")
    return run_pack(TargetConfig(adapter="mock", model="naive-demo"), pack)


def test_run_to_dict_shape():
    run = make_run()
    data = run_to_dict(run)
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["tool"]["name"] == "promptrampart"
    assert data["target"] == "mock:naive-demo"
    assert data["pack"] == "core"
    assert len(data["results"]) == len(run.results)


def test_summary_counts_consistent():
    run = make_run()
    summary = run_to_dict(run)["summary"]
    assert summary["attacks_run"] == len(run.results)
    assert summary["resisted"] + summary["breached"] + summary["errors"] == len(
        run.results
    )
    assert (
        sum(summary["breached_by_severity"].values()) == summary["breached"]
    )


def test_result_entries_have_detections():
    run = make_run()
    data = run_to_dict(run)
    for entry in data["results"]:
        assert entry["verdict"] in ("PASS", "FAIL", "ERROR")
        assert isinstance(entry["detections"], list)
        if entry["verdict"] == "FAIL":
            assert any(d["fired"] for d in entry["detections"])


def test_compute_grade_bands():
    from promptrampart.report import compute_grade

    assert compute_grade(100, 0) == "A"
    assert compute_grade(90, 0) == "B"
    assert compute_grade(75, 0) == "C"
    assert compute_grade(55, 0) == "D"
    assert compute_grade(30, 0) == "F"


def test_critical_breach_caps_grade():
    from promptrampart.report import compute_grade

    assert compute_grade(100, 1) == "C"
    assert compute_grade(90, 2) == "C"
    # Already low grades stay as they are.
    assert compute_grade(55, 1) == "D"


def test_write_html_report(tmp_path):
    from promptrampart.report import write_html

    run = make_run()
    out = tmp_path / "report.html"
    written = write_html(run, out)
    assert written.is_file()
    html = written.read_text(encoding="utf-8")
    assert "PromptRampart security report card" in html
    assert run.target_label in html
    # Every attack id must appear in the transcript section.
    for result in run.results:
        assert result.attack.id in html
    # Verdict pills present.
    assert 'class="pill PASS"' in html
    assert 'class="pill FAIL"' in html


def test_html_escapes_model_output(tmp_path):
    """Hostile model output must not inject script tags into the report."""
    from promptrampart.report import write_html
    from promptrampart.runner import AttackResult
    from promptrampart.pack import Attack
    from promptrampart.runner import RunResult

    attack = Attack(
        id="X-001",
        category="test",
        severity="low",
        title="xss probe",
        prompt="<script>alert(1)</script>",
        detectors=[{"type": "regex", "pattern": "x"}],
    )
    run = RunResult(target_label="mock:x", pack_name="t", canary="RAMPART-AAAAA11111")
    run.results.append(
        AttackResult(
            attack=attack,
            response="<script>alert('pwned')</script>",
            attack_succeeded=False,
            detections=[],
            duration_s=0.1,
        )
    )
    out = tmp_path / "xss.html"
    html = write_html(run, out).read_text(encoding="utf-8")
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_write_json_roundtrip(tmp_path):
    run = make_run()
    out = tmp_path / "nested" / "results.json"
    written = write_json(run, out)
    assert written.is_file()
    loaded = json.loads(written.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == SCHEMA_VERSION
    assert loaded["summary"]["attacks_run"] == len(run.results)
