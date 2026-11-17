from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from vbeye import __version__
from vbeye.checkers import headers, source, ssl
from vbeye.context import ScanContext
from vbeye.net import fetch
from vbeye.scoring import CheckerResult, Severity, compute_score

CHECKERS: dict[str, Callable[[ScanContext], CheckerResult]] = {
    "headers": headers.run,
    "ssl": ssl.run,
    "source": source.run,
}

MODULES = tuple(CHECKERS)


@dataclass
class ScanReport:
    target: str
    results: list[CheckerResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration: float = 0.0

    @property
    def score(self) -> int:
        return compute_score(self.results)[0]

    @property
    def grade(self) -> str:
        return compute_score(self.results)[1]

    @property
    def host(self) -> str:
        return urlparse(self.target).hostname or self.target

    def severity_counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for r in self.results:
            for f in r.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        score, grade = compute_score(self.results)
        return {
            "tool": "vbeye",
            "version": __version__,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "duration_sec": round(self.duration, 2),
            "score": score,
            "grade": grade,
            "results": [r.to_dict() for r in self.results],
        }


def normalize_target(target: str) -> str:
    t = target.strip()
    if "://" not in t:
        t = f"https://{t}"
    return t


def slug(target: str) -> str:
    host = urlparse(normalize_target(target)).hostname or "target"
    return host.replace(".", "_")


ModuleCallback = Callable[[str, CheckerResult, float], None]


def scan(
    target: str,
    *,
    skip: Iterable[str] = (),
    timeout: int = 15,
    user_agent: str | None = None,
    on_module: ModuleCallback | None = None,
) -> ScanReport:
    url = normalize_target(target)
    skipped = set(skip)
    report = ScanReport(target=url)
    t_start = time.monotonic()

    ctx = ScanContext(url=url, timeout=timeout, page=fetch(url, timeout, user_agent))

    for name, runner in CHECKERS.items():
        if name in skipped:
            continue
        t0 = time.monotonic()
        try:
            result = runner(ctx)
        except Exception as e:
            result = CheckerResult(name=name, error=f"Internal error: {type(e).__name__}: {e}")
        if on_module:
            on_module(name, result, time.monotonic() - t0)
        report.results.append(result)

    report.duration = time.monotonic() - t_start
    return report
