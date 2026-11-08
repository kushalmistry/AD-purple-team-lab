"""
Every rule in detections/ must:
  1. carry required metadata (id, ATT&CK tag, level, false positives)
  2. fire on every event in tests/fixtures/<rule_stem>/positive.jsonl
  3. stay silent on every event in tests/fixtures/<rule_stem>/negative.jsonl
"""

import re
import uuid
from pathlib import Path

import pytest

from sigma_lite import load_events, load_rule, rule_matches

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "detections").glob("*.yml"))
FIXTURES = ROOT / "tests" / "fixtures"
ATTACK_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def fixture(rule_path: Path, kind: str) -> list[dict]:
    path = FIXTURES / rule_path.stem / f"{kind}.jsonl"
    assert path.exists(), f"missing fixture: {path.relative_to(ROOT)}"
    events = load_events(path)
    assert events, f"empty fixture: {path.relative_to(ROOT)}"
    return events


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_metadata(rule_path):
    rule = load_rule(rule_path)
    uuid.UUID(rule["id"])
    assert rule["level"] in {"informational", "low", "medium", "high", "critical"}
    assert any(ATTACK_TAG.match(t) for t in rule.get("tags", [])), "needs an ATT&CK technique tag"
    assert rule.get("falsepositives"), "document expected false positives"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_fires_on_true_positives(rule_path):
    rule = load_rule(rule_path)
    missed = [e for e in fixture(rule_path, "positive") if not rule_matches(rule, e)]
    assert not missed, f"rule did not fire on {len(missed)} positive event(s): {missed}"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_silent_on_benign(rule_path):
    rule = load_rule(rule_path)
    noisy = [e for e in fixture(rule_path, "negative") if rule_matches(rule, e)]
    assert not noisy, f"rule fired on {len(noisy)} benign event(s): {noisy}"


def test_rule_ids_unique():
    ids = [load_rule(p)["id"] for p in RULES]
    assert len(ids) == len(set(ids))
