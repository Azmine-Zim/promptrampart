"""End-to-end tests for the runner using the offline mock adapter."""

from promptarmor.config import TargetConfig
from promptarmor.pack import load_pack
from promptarmor.runner import run_pack


def mock_config():
    return TargetConfig(adapter="mock", model="naive-demo")


def test_run_pack_completes_all_attacks():
    pack = load_pack("core")
    run = run_pack(mock_config(), pack)
    assert len(run.results) == len(pack.attacks)
    assert run.errored == 0
    assert run.passed + run.failed == len(pack.attacks)


def test_run_pack_plants_canary_in_system_prompt():
    pack = load_pack("core")
    run = run_pack(mock_config(), pack)
    assert run.canary.startswith("ARMOR-")
    # The placeholder must never be sent raw.
    assert "{{CANARY}}" not in run.canary


def test_on_result_callback_streams_every_result():
    pack = load_pack("core")
    seen = []
    run_pack(mock_config(), pack, on_result=lambda r: seen.append(r.attack.id))
    assert seen == [attack.id for attack in pack.attacks]


def test_mock_demo_shows_both_pass_and_fail():
    """The offline demo should show resisted AND breached attacks."""
    pack = load_pack("core")
    run = run_pack(mock_config(), pack)
    assert run.passed > 0
    assert run.failed > 0
    # The canary leaks must be what breaks the naive mock.
    breached = [r for r in run.results if r.verdict == "FAIL"]
    assert any(
        d.detector_type in ("canary", "canary_spaced") and d.fired
        for r in breached
        for d in r.detections
    )


def test_category_summary_counts_add_up():
    pack = load_pack("core")
    run = run_pack(mock_config(), pack)
    stats = run.by_category()
    total = sum(sum(bucket.values()) for bucket in stats.values())
    assert total == len(pack.attacks)


def test_adapter_connection_error_becomes_error_verdict():
    config = TargetConfig(
        adapter="ollama", model="ghost", base_url="http://localhost:1", timeout=2
    )
    pack = load_pack("core")
    run = run_pack(config, pack)
    assert run.errored == len(pack.attacks)
    assert all(r.verdict == "ERROR" for r in run.results)
