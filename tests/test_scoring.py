from __future__ import annotations

import pytest

from vbeye.scoring import (
    CATEGORY_CEILING,
    ERROR_PENALTY,
    CheckerResult,
    Finding,
    Severity,
    compute_score,
    grade_from_score,
)


def finding(check_id: str, severity: Severity) -> Finding:
    return Finding(check_id=check_id, title=check_id, severity=severity, description="")


@pytest.mark.parametrize(
    ("score", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (79, "C"), (65, "C"), (64, "D"), (50, "D"), (49, "E"),
     (30, "E"), (29, "F"), (0, "F")],
)
def test_grade_thresholds(score, grade):
    assert grade_from_score(score) == grade


def test_clean_scan_scores_100():
    results = [CheckerResult("headers", [finding("headers.ok", Severity.OK)])]
    assert compute_score(results) == (100, "A")


def test_category_ceiling_caps_hardening_findings():
    findings = [finding(f"headers.x{i}", Severity.MEDIUM) for i in range(10)]
    score, _ = compute_score([CheckerResult("headers", findings)])
    assert score == 100 - CATEGORY_CEILING["headers"]


def test_real_risk_bypasses_ceiling():
    findings = [finding(f"source.x{i}", Severity.MEDIUM) for i in range(10)]
    findings.append(finding("source.secret.exposed", Severity.CRITICAL))
    score, _ = compute_score([CheckerResult("source", findings)])
    assert score == 100 - CATEGORY_CEILING["source"] - 35


def test_three_highs_in_category_bypass_ceiling():
    findings = [finding(f"headers.h{i}", Severity.HIGH) for i in range(3)]
    score, _ = compute_score([CheckerResult("headers", findings)])
    assert score == 100 - 3 * 18


def test_floor_without_real_risk():
    results = [
        CheckerResult("headers", [finding(f"headers.m{i}", Severity.MEDIUM) for i in range(10)]),
        CheckerResult("source", [finding(f"source.m{i}", Severity.MEDIUM) for i in range(10)]),
    ]
    assert compute_score(results) == (30, "E")


def test_real_risk_allows_f():
    results = [
        CheckerResult("ssl", [
            finding("ssl.no_tls", Severity.CRITICAL),
            finding("ssl.cert.expired", Severity.CRITICAL),
        ]),
        CheckerResult("headers", [finding(f"headers.m{i}", Severity.MEDIUM) for i in range(10)]),
    ]
    score, grade = compute_score(results)
    assert score < 30
    assert grade == "F"


def test_protocol_relative_is_not_real_risk():
    results = [CheckerResult("source", [finding("source.mixed_content.protocol_relative", Severity.LOW)])]
    assert compute_score(results) == (97, "A")


def test_checker_error_costs_fixed_penalty():
    results = [CheckerResult("ssl", [finding("ssl.no_tls", Severity.CRITICAL)], error="timeout")]
    assert compute_score(results)[0] == 100 - ERROR_PENALTY


def test_unknown_category_uses_default_ceiling():
    findings = [finding(f"dns.x{i}", Severity.MEDIUM) for i in range(10)]
    assert compute_score([CheckerResult("dns", findings)])[0] == 70
