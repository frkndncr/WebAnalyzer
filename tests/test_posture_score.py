"""The score is the Security Analysis score minus findings from the other modules."""
import pytest

from utils.result_analysis import (
    MODULE_PENALTY_CAP, TOTAL_PENALTY_CAP, grade_for, posture_score, summarize_security_result,
)


def results(base=90, grade="A", **modules):
    return {"Security Analysis": {"security_score": {"overall_score": base, "grade": grade}}, **modules}


def plugin(*severities):
    return {"findings": [{"title": f"issue {i}", "severity": s} for i, s in enumerate(severities)]}


def test_without_other_findings_the_modules_own_score_and_grade_are_kept():
    assert posture_score(results(83, "B")) == {"score": 83, "grade": "B", "base": 83, "penalty": 0}


def test_findings_from_other_modules_lower_the_score_and_regrade_it():
    out = posture_score(results(90, "A", **{"Email Security": plugin("high", "medium")}))     # 7 + 3
    assert out == {"score": 80, "grade": "B", "base": 90, "penalty": 10}


def test_security_analysis_findings_are_not_counted_twice():
    res = results(90, "A")
    res["Security Analysis"]["vulnerability_scan"] = {"vulnerabilities": [{"type": "X", "severity": "Critical"}]}
    assert posture_score(res)["penalty"] == 0


def test_info_findings_cost_nothing():
    assert posture_score(results(90, "A", **{"Security.txt": plugin("info", "info")}))["penalty"] == 0


def test_one_noisy_module_is_capped_and_so_is_the_total():
    noisy = {"Exposed Files": plugin(*["critical"] * 10)}
    assert posture_score(results(100, "A+", **noisy))["penalty"] == MODULE_PENALTY_CAP
    many = {f"M{i}": plugin("critical", "critical") for i in range(6)}
    assert posture_score(results(100, "A+", **many))["penalty"] == TOTAL_PENALTY_CAP


def test_the_score_never_goes_below_zero():
    many = {f"M{i}": plugin("critical", "critical") for i in range(6)}
    assert posture_score(results(10, "F", **many))["score"] == 0


def test_no_security_analysis_means_no_score_rather_than_an_invented_one():
    assert posture_score({"Email Security": plugin("high")}) == {"score": None, "grade": None, "base": None, "penalty": 0}


@pytest.mark.parametrize("score,grade", [(100, "A+"), (95, "A+"), (94, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (70, "C"), (69, "D"), (60, "D"), (59, "F"), (0, "F")])
def test_grade_bands_match_the_security_analysis_module(score, grade):
    from modules.security_analysis import get_security_grade
    assert grade_for(score) == get_security_grade(score) == grade


def test_summaries_use_the_adjusted_score():
    score, grade, count = summarize_security_result(results(90, "A", **{"Exposed Files": plugin("critical")}))
    assert (score, grade, count) == (78, "C", 1)
