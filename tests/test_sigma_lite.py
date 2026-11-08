import pytest

from sigma_lite import SigmaLiteError, evaluate_condition, rule_matches


def test_condition_precedence():
    r = {"a": True, "b": False, "c": True}
    assert evaluate_condition("a and b or c", r) is True
    assert evaluate_condition("a and (b or not c)", r) is False
    assert evaluate_condition("1 of a*", r) is True


def test_one_of_and_all_of():
    r = {"filter_x": False, "filter_y": True, "selection": True}
    assert evaluate_condition("selection and not 1 of filter_*", r) is False
    assert evaluate_condition("selection and not all of filter_*", r) is True


def test_unknown_selection_raises():
    with pytest.raises(SigmaLiteError):
        evaluate_condition("missing", {"a": True})


def test_logsource_gate():
    rule = {
        "logsource": {"product": "windows", "service": "security"},
        "detection": {"sel": {"EventID": 4624}, "condition": "sel"},
    }
    assert rule_matches(rule, {"Channel": "Security", "EventID": 4624})
    assert not rule_matches(rule, {"Channel": "System", "EventID": 4624})


def test_modifiers():
    rule = {
        "logsource": {"product": "windows", "service": "system"},
        "detection": {
            "sel": {"ImagePath|contains|all": ["foo", "bar"], "Name|endswith": "$"},
            "condition": "sel",
        },
    }
    assert rule_matches(rule, {"Channel": "System", "ImagePath": "x FOO y BAR", "Name": "DC01$"})
    assert not rule_matches(rule, {"Channel": "System", "ImagePath": "x foo", "Name": "DC01$"})
