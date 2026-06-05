from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    OK = "ok"


class Confidence(str, Enum):
    VERIFIED = "verified"
    STRONG_INDICATOR = "strong_indicator"
    REQUIRES_MANUAL_VALIDATION = "requires_manual_validation"


CONFIDENCE_LABEL = {
    Confidence.VERIFIED: "VERIFIED",
    Confidence.STRONG_INDICATOR: "STRONG INDICATOR",
    Confidence.REQUIRES_MANUAL_VALIDATION: "KÉZI ELLENŐRZÉS SZÜKSÉGES",
}


SEVERITY_WEIGHT = {
    Severity.OK: 0,
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 18,
    Severity.CRITICAL: 35,
}


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
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    if score >= 30:
        return "E"
    return "F"


def compute_score(results: list[CheckerResult]) -> tuple[int, str]:
    penalty = 0
    for r in results:
        if r.error:
            penalty += 15
            continue
        for f in r.findings:
            penalty += SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, 100 - penalty)
    return score, grade_from_score(score)
