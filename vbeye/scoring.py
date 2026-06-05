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


# Maximum penalty a single category can contribute. A site that only fails
# hardening (headers) cannot be punished as severely as one with broken TLS
# or leaked secrets — the categories are not comparable in business impact.
CATEGORY_CEILING = {
    "headers": 30,
    "source": 35,
    "ssl": 50,
}
DEFAULT_CATEGORY_CEILING = 30

# Treated as "real" risk markers when deciding whether F is justified.
# A hardening-gap-only site (no items below + no 3+ HIGHs) cannot drop below E.
REAL_RISK_CHECK_IDS = frozenset({
    "ssl.no_tls",
    "ssl.cert.expired",
    "ssl.protocol.no_modern",
    "ssl.protocol.ssl_2_0_cipher_suites",
    "source.form.password_on_http",
    "source.mixed_content",
    "source.secret.exposed",
})

# Per-category penalty for a checker that errored out (timeout, connect refused).
# Lower than the previous flat 15 — an unreachable subsystem is "data unavailable",
# not a security finding.
ERROR_PENALTY = 5


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


def _has_real_risk(results: list[CheckerResult]) -> bool:
    high_count = 0
    for r in results:
        for f in r.findings:
            if f.check_id in REAL_RISK_CHECK_IDS:
                return True
            if f.severity == Severity.HIGH:
                high_count += 1
    return high_count >= 3


def compute_score(results: list[CheckerResult]) -> tuple[int, str]:
    total_penalty = 0
    for r in results:
        ceiling = CATEGORY_CEILING.get(r.name, DEFAULT_CATEGORY_CEILING)
        if r.error:
            total_penalty += min(ERROR_PENALTY, ceiling)
            continue
        cat_penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in r.findings)
        total_penalty += min(cat_penalty, ceiling)

    score = max(0, 100 - total_penalty)
    # Hardening-gap-only sites (no critical TLS/HTTP/secret issue, fewer than
    # 3 HIGH findings total) cannot drop below E — that protects the report
    # against the "everything is F" reflex on modern WordPress / static sites.
    if score < 30 and not _has_real_risk(results):
        score = 30
    return score, grade_from_score(score)
