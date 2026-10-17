"""Tests for the JSON results export."""

import json

from promptarmor.config import TargetConfig
from promptarmor.pack import load_pack
from promptarmor.report import SCHEMA_VERSION, run_to_dict, write_json
from promptarmor.runner import run_pack


def make_run():
    pack = load_pack("core")
    return run_pack(TargetConfig(adapter="mock", model="naive-demo"), pack)


def test_run_to_dict_shape():
    run = make_run()
    data = run_to_dict(run)
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["tool"]["name"] == "promptarmor"
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


def test_write_json_roundtrip(tmp_path):
    run = make_run()
    out = tmp_path / "nested" / "results.json"
    written = write_json(run, out)
    assert written.is_file()
    loaded = json.loads(written.read_text(encoding="utf-8"))
    assert loaded["schema_version"] == SCHEMA_VERSION
    assert loaded["summary"]["attacks_run"] == len(run.results)
