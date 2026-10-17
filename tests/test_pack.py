"""Tests for attack pack loading."""

import pytest

from promptrampart.pack import PackError, load_pack


def test_builtin_core_pack_loads():
    pack = load_pack("core")
    assert pack.name == "core"
    # M2 scope: 40 to 60 curated attacks.
    assert 40 <= len(pack.attacks) <= 60
    assert "{{CANARY}}" in pack.default_system_prompt


def test_each_category_has_enough_coverage():
    pack = load_pack("core")
    counts = {}
    for attack in pack.attacks:
        counts[attack.category] = counts.get(attack.category, 0) + 1
    for category, count in counts.items():
        assert count >= 8, f"category '{category}' only has {count} attacks"


def test_core_pack_covers_required_categories():
    pack = load_pack("core")
    categories = {attack.category for attack in pack.attacks}
    assert {
        "prompt_injection",
        "jailbreak",
        "system_prompt_leak",
        "data_exfiltration",
        "roleplay_escape",
    } <= categories


def test_core_pack_ids_unique_and_detectors_present():
    pack = load_pack("core")
    ids = [attack.id for attack in pack.attacks]
    assert len(ids) == len(set(ids))
    assert all(attack.detectors for attack in pack.attacks)


def test_load_pack_from_path(tmp_path):
    path = tmp_path / "mini.yaml"
    path.write_text(
        "name: mini\n"
        "default_system_prompt: 'Token {{CANARY}}.'\n"
        "attacks:\n"
        "  - id: X-001\n"
        "    category: test\n"
        "    severity: low\n"
        "    title: sample\n"
        "    prompt: say hi\n"
        "    detectors:\n"
        "      - type: regex\n"
        "        pattern: hi\n",
        encoding="utf-8",
    )
    pack = load_pack(str(path))
    assert pack.name == "mini"
    assert pack.attacks[0].id == "X-001"


def test_unknown_pack_raises():
    with pytest.raises(PackError, match="not found"):
        load_pack("does-not-exist")


def test_duplicate_ids_raise(tmp_path):
    path = tmp_path / "dup.yaml"
    path.write_text(
        "attacks:\n"
        "  - {id: A, category: c, severity: low, title: t, prompt: p,"
        " detectors: [{type: regex, pattern: x}]}\n"
        "  - {id: A, category: c, severity: low, title: t, prompt: p,"
        " detectors: [{type: regex, pattern: x}]}\n",
        encoding="utf-8",
    )
    with pytest.raises(PackError, match="Duplicate"):
        load_pack(str(path))


def test_invalid_severity_raises(tmp_path):
    path = tmp_path / "sev.yaml"
    path.write_text(
        "attacks:\n"
        "  - {id: A, category: c, severity: apocalyptic, title: t, prompt: p,"
        " detectors: [{type: regex, pattern: x}]}\n",
        encoding="utf-8",
    )
    with pytest.raises(PackError, match="severity"):
        load_pack(str(path))


def test_missing_detectors_raise(tmp_path):
    path = tmp_path / "nodet.yaml"
    path.write_text(
        "attacks:\n"
        "  - {id: A, category: c, severity: low, title: t, prompt: p}\n",
        encoding="utf-8",
    )
    with pytest.raises(PackError, match="detector"):
        load_pack(str(path))
