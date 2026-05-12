from __future__ import annotations

import html
from datetime import datetime

from vbeye import __version__
from vbeye.scoring import CheckerResult, Severity, compute_score


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.OK,
]

SEVERITY_LABEL = {
    Severity.CRITICAL: "KRITIKUS",
    Severity.HIGH: "MAGAS",
    Severity.MEDIUM: "KÖZEPES",
    Severity.LOW: "ALACSONY",
    Severity.INFO: "INFO",
    Severity.OK: "OK",
}

GRADE_COLOR = {
    "A": "#16a34a",
    "B": "#65a30d",
    "C": "#ca8a04",
    "D": "#ea580c",
    "E": "#dc2626",
    "F": "#991b1b",
}

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  margin: 0; padding: 0; background: #f3f4f6; color: #111827;
}
header {
  background: #0f172a; color: #f8fafc; padding: 24px 32px;
  display: flex; align-items: center; gap: 24px; flex-wrap: wrap;
}
header h1 { margin: 0; font-size: 22px; font-weight: 600; }
header .meta { font-size: 13px; color: #cbd5e1; }
.score-badge {
  margin-left: auto; display: flex; align-items: center; gap: 16px;
  background: rgba(255,255,255,0.08); padding: 12px 20px; border-radius: 8px;
}
.score-grade { font-size: 42px; font-weight: 700; line-height: 1; }
.score-num { font-size: 14px; color: #cbd5e1; }
main { max-width: 1100px; margin: 24px auto; padding: 0 24px; }
.summary {
  background: white; padding: 16px 20px; border-radius: 8px; margin-bottom: 20px;
  display: flex; gap: 12px; flex-wrap: wrap;
}
.summary-pill {
  padding: 6px 12px; border-radius: 999px; font-size: 13px;
  font-weight: 600; display: inline-flex; align-items: center; gap: 6px;
}
.section {
  background: white; border-radius: 8px; margin-bottom: 16px;
  overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}
.section-header {
  padding: 14px 20px; background: #f9fafb; border-bottom: 1px solid #e5e7eb;
  display: flex; align-items: center; gap: 12px;
}
.section-header h2 { margin: 0; font-size: 16px; }
.section-meta { font-size: 12px; color: #6b7280; }
.finding {
  padding: 14px 20px; border-bottom: 1px solid #f3f4f6;
}
.finding:last-child { border-bottom: none; }
.finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.finding-title { font-weight: 600; font-size: 14px; }
.finding-id { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 11px; color: #6b7280; }
.finding-body { font-size: 13px; line-height: 1.5; color: #374151; }
.finding-rec {
  margin-top: 8px; padding: 10px 12px; background: #eff6ff;
  border-left: 3px solid #3b82f6; font-size: 13px; border-radius: 0 4px 4px 0;
}
.finding-rec strong { color: #1e3a8a; }
.finding-evidence {
  margin-top: 8px; padding: 10px 12px; background: #1f2937; color: #e5e7eb;
  font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12px;
  border-radius: 4px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow: auto;
}
.sev-tag {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 700; letter-spacing: 0.5px;
}
.sev-critical { background: #991b1b; color: white; }
.sev-high     { background: #dc2626; color: white; }
.sev-medium   { background: #ea580c; color: white; }
.sev-low      { background: #ca8a04; color: white; }
.sev-info     { background: #6b7280; color: white; }
.sev-ok       { background: #16a34a; color: white; }
.error-banner {
  padding: 12px 20px; background: #fef2f2; color: #991b1b;
  border-left: 3px solid #dc2626; font-size: 13px;
}
footer {
  text-align: center; padding: 24px; font-size: 12px; color: #6b7280;
}
"""


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _severity_class(sev: Severity) -> str:
    return f"sev-{sev.value}"


def _count_by_severity(results: list[CheckerResult]) -> dict[Severity, int]:
    counts: dict[Severity, int] = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for f in r.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _section_html(r: CheckerResult) -> str:
    findings = sorted(
        r.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
    )
    body = []
    if r.error:
        body.append(f'<div class="error-banner"><strong>Hiba:</strong> {_esc(r.error)}</div>')

    for f in findings:
        rec = f'<div class="finding-rec"><strong>Javaslat:</strong> {_esc(f.recommendation)}</div>' if f.recommendation else ""
        ev = f'<div class="finding-evidence">{_esc(f.evidence)}</div>' if f.evidence else ""
        body.append(
            f'<div class="finding">'
            f'  <div class="finding-head">'
            f'    <span class="sev-tag {_severity_class(f.severity)}">{SEVERITY_LABEL[f.severity]}</span>'
            f'    <span class="finding-title">{_esc(f.title)}</span>'
            f'    <span class="finding-id">{_esc(f.check_id)}</span>'
            f'  </div>'
            f'  <div class="finding-body">{_esc(f.description)}</div>'
            f'  {rec}'
            f'  {ev}'
            f'</div>'
        )

    meta_bits = []
    for k, v in r.meta.items():
        if k == "headers":  # túl hosszú
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        meta_bits.append(f"{_esc(str(k))}: {_esc(str(v))[:200]}")
    meta_html = f'<div class="section-meta">{" · ".join(meta_bits)}</div>' if meta_bits else ""

    return (
        f'<section class="section">'
        f'  <div class="section-header">'
        f'    <h2>{_esc(r.name.upper())}</h2>'
        f'    {meta_html}'
        f'  </div>'
        f'  {"".join(body)}'
        f'</section>'
    )


def build_html(target: str, results: list[CheckerResult]) -> str:
    score, grade = compute_score(results)
    counts = _count_by_severity(results)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    pills = []
    for sev in SEVERITY_ORDER:
        if sev == Severity.OK:
            continue
        n = counts.get(sev, 0)
        if n == 0:
            continue
        pills.append(
            f'<span class="summary-pill {_severity_class(sev)}">{SEVERITY_LABEL[sev]}: {n}</span>'
        )
    if not pills:
        pills.append('<span class="summary-pill sev-ok">Nincs találat</span>')

    sections = "\n".join(_section_html(r) for r in results)
    grade_color = GRADE_COLOR.get(grade, "#6b7280")

    return f"""<!doctype html>
<html lang="hu">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vbeye — {_esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
<header>
  <div>
    <h1>vbeye jelentés</h1>
    <div class="meta">Cél: <strong>{_esc(target)}</strong> · Időpont: {now}</div>
  </div>
  <div class="score-badge">
    <div>
      <div class="score-grade" style="color: {grade_color}">{grade}</div>
      <div class="score-num">{score}/100</div>
    </div>
  </div>
</header>
<main>
  <div class="summary">
    {"".join(pills)}
  </div>
  {sections}
</main>
<footer>
  Generated with <strong>vbeye v{__version__}</strong> — Passive Web Security Assessment Tool<br>
  Developed by theEreb0x · scoring: 100 - súlyozott találat-büntetés (max 0)
</footer>
</body>
</html>
"""
