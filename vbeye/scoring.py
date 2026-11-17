from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    OK = "ok"


SEVERITY_RANK = {
    Severity.OK: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class Confidence(str, Enum):
    VERIFIED = "verified"
    STRONG_INDICATOR = "strong_indicator"
    REQUIRES_MANUAL_VALIDATION = "requires_manual_validation"


CONFIDENCE_LABEL = {
    Confidence.VERIFIED: "VERIFIED",
    Confidence.STRONG_INDICATOR: "STRONG INDICATOR",
    Confidence.REQUIRES_MANUAL_VALIDATION: "MANUAL VALIDATION REQUIRED",
}

SEVERITY_WEIGHT = {
    Severity.OK: 0,
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 18,
    Severity.CRITICAL: 35,
}

CATEGORY_CEILING = {
    "headers": 45,
    "source": 35,
    "ssl": 50,
}
DEFAULT_CATEGORY_CEILING = 30

REAL_RISK_CHECK_IDS = frozenset({
    "ssl.no_tls",
    "ssl.cert.expired",
    "ssl.protocol.no_modern",
    "ssl.protocol.ssl_2_0_cipher_suites",
    "source.form.password_on_http",
    "source.mixed_content",
    "source.secret.exposed",
    "headers.tech.php_eol",
    "headers.cookie.session_flags",
})

ERROR_PENALTY = 5
SYSTEMIC_HIGH_COUNT = 3
GRADE_FLOOR_SCORE = 30

GRADE_THRESHOLDS = (
    (90, "A"),
    (80, "B"),
    (65, "C"),
    (50, "D"),
    (30, "E"),
)


@dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    evidence: str = ""
    confidence: Confidence = Confidence.STRONG_INDICATOR

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
            "confidence": self.confidence.value,
        }


@dataclass
class CheckerResult:
    name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "meta": self.meta,
        }


def grade_from_score(score: int) -> str:
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _has_real_risk(results: list[CheckerResult]) -> bool:
    high_count = 0
    for r in results:
        for f in r.findings:
            if f.check_id in REAL_RISK_CHECK_IDS:
                return True
            if f.severity == Severity.HIGH:
                high_count += 1
    return high_count >= SYSTEMIC_HIGH_COUNT


def _category_penalty(result: CheckerResult) -> int:
    ceiling = CATEGORY_CEILING.get(result.name, DEFAULT_CATEGORY_CEILING)
    if result.error:
        return min(ERROR_PENALTY, ceiling)

    real_risk = 0
    capped = 0
    high_count = 0
    for f in result.findings:
        weight = SEVERITY_WEIGHT.get(f.severity, 0)
        if f.check_id in REAL_RISK_CHECK_IDS:
            real_risk += weight
        else:
            capped += weight
        if f.severity == Severity.HIGH:
            high_count += 1

    if high_count >= SYSTEMIC_HIGH_COUNT:
        return capped + real_risk
    return min(capped, ceiling) + real_risk


def compute_score(results: list[CheckerResult]) -> tuple[int, str]:
    penalty = sum(_category_penalty(r) for r in results)
    score = max(0, 100 - penalty)
    if score < GRADE_FLOOR_SCORE and not _has_real_risk(results):
        score = GRADE_FLOOR_SCORE
    return score, grade_from_score(score)
