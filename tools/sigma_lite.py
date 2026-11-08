"""
sigma_lite: a small, dependency-light Sigma evaluator for offline detection testing.

It replays flattened Windows events (JSON Lines) against Sigma rules so every rule
can be unit tested in CI without a SIEM. It intentionally supports only the subset of
Sigma used in this repo:

  * logsources: windows/security, windows/system, windows/sysmon (+ network_connection, process_creation)
  * modifiers: contains, startswith, endswith, re, all, cased
  * conditions: and / or / not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them"

Production conversion is handled by pySigma (see the CI workflow); this module only
answers "does this rule fire on this event?".
"""

from __future__ import annotations

import json
import re
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Iterable

import yaml

SYSMON = "Microsoft-Windows-Sysmon/Operational"

# (product, service, category) -> fields an event must have for the rule to apply
LOGSOURCE_MAP: dict[tuple, dict[str, Any]] = {
    ("windows", "security", None): {"Channel": "Security"},
    ("windows", "system", None): {"Channel": "System"},
    ("windows", "sysmon", None): {"Channel": SYSMON},
    ("windows", None, "process_creation"): {"Channel": SYSMON, "EventID": 1},
    ("windows", None, "network_connection"): {"Channel": SYSMON, "EventID": 3},
}

RESERVED_KEYS = {"condition", "timeframe"}
TOKEN_RE = re.compile(r"\(|\)|[\w\*]+")


class SigmaLiteError(ValueError):
    """Raised when a rule uses Sigma features this evaluator does not support."""


def load_rule(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_events(path: str | Path) -> list[dict]:
    # utf-8-sig tolerates the BOM that Windows PowerShell 5 writes
    with open(path, encoding="utf-8-sig") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def logsource_requirements(logsource: dict) -> dict[str, Any]:
    key = (logsource.get("product"), logsource.get("service"), logsource.get("category"))
    if key not in LOGSOURCE_MAP:
        raise SigmaLiteError(f"Unsupported logsource: {logsource}")
    return LOGSOURCE_MAP[key]


def _compare(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if expected is None:
        return actual in (None, "")
    if actual is None:
        return False
    if "re" in modifiers:
        return re.search(str(expected), str(actual)) is not None

    a, e = str(actual), str(expected)
    if "cased" not in modifiers:
        a, e = a.lower(), e.lower()
    if "contains" in modifiers:
        return e in a
    if "startswith" in modifiers:
        return a.startswith(e)
    if "endswith" in modifiers:
        return a.endswith(e)
    return a == e


def _match_field(event: dict, key: str, expected: Any) -> bool:
    field, *modifiers = key.split("|")
    unknown = set(modifiers) - {"contains", "startswith", "endswith", "re", "all", "cased"}
    if unknown:
        raise SigmaLiteError(f"Unsupported modifier(s) {unknown} in '{key}'")
    values = expected if isinstance(expected, list) else [expected]
    results = [_compare(event.get(field), v, modifiers) for v in values]
    return all(results) if "all" in modifiers else any(results)


def _match_selection(event: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    if isinstance(selection, list):
        if any(not isinstance(item, dict) for item in selection):
            raise SigmaLiteError("Keyword (full-text) selections are not supported")
        return any(_match_selection(event, item) for item in selection)
    raise SigmaLiteError(f"Unsupported selection type: {type(selection).__name__}")


def evaluate_condition(condition: str, results: dict[str, bool]) -> bool:
    tokens = TOKEN_RE.findall(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise SigmaLiteError(f"Unexpected end of condition: {condition!r}")
        tok = tokens[pos]
        pos += 1
        return tok

    def expr() -> bool:
        value = term()
        while peek() == "or":
            take()
            rhs = term()  # always parse, then combine (no short-circuit on tokens)
            value = value or rhs
        return value

    def term() -> bool:
        value = factor()
        while peek() == "and":
            take()
            rhs = factor()
            value = value and rhs
        return value

    def factor() -> bool:
        tok = take()
        if tok == "not":
            return not factor()
        if tok == "(":
            value = expr()
            if take() != ")":
                raise SigmaLiteError(f"Unbalanced parentheses in {condition!r}")
            return value
        if tok in ("1", "all") and peek() == "of":
            take()
            target = take()
            names = list(results) if target == "them" else [n for n in results if fnmatch(n, target)]
            if not names:
                raise SigmaLiteError(f"'{tok} of {target}' matched no selections")
            values = [results[n] for n in names]
            return any(values) if tok == "1" else all(values)
        if tok not in results:
            raise SigmaLiteError(f"Unknown selection '{tok}' in condition")
        return results[tok]

    value = expr()
    if pos != len(tokens):
        raise SigmaLiteError(f"Trailing tokens in condition: {tokens[pos:]}")
    return value


def rule_matches(rule: dict, event: dict) -> bool:
    for field, required in logsource_requirements(rule["logsource"]).items():
        if str(event.get(field)) != str(required):
            return False

    detection = rule["detection"]
    results = {
        name: _match_selection(event, sel)
        for name, sel in detection.items()
        if name not in RESERVED_KEYS
    }
    condition = detection["condition"]
    conditions = condition if isinstance(condition, list) else [condition]
    return any(evaluate_condition(c, results) for c in conditions)


def run(rule_paths: Iterable[Path], events: list[dict]) -> list[tuple[str, dict]]:
    hits = []
    for path in rule_paths:
        rule = load_rule(path)
        hits.extend((rule["title"], e) for e in events if rule_matches(rule, e))
    return hits


if __name__ == "__main__":
    # Usage: python tools/sigma_lite.py <events.jsonl> [rules_dir]
    if len(sys.argv) < 2:
        sys.exit("usage: sigma_lite.py <events.jsonl> [rules_dir]")
    rules_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "detections")
    hits = run(sorted(rules_dir.glob("*.yml")), load_events(sys.argv[1]))
    for title, event in hits:
        print(f"[HIT] {title} | {event.get('Computer', '?')} | {event.get('TimeCreated', '?')}")
    print(f"{len(hits)} hit(s)")
