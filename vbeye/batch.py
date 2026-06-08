"""Batch scanning: run vbeye over many targets in parallel.

Used by `vbeye --batch targets.txt`. Outputs go into a single timestamped
directory under ./reports/batch_<ts>/, with a summary CSV at the root.
"""
from __future__ import annotations

import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from vbeye.checkers import headers as headers_check
from vbeye.checkers import ssl as ssl_check
from vbeye.checkers import source as source_check
from vbeye.docx_report import build as build_docx
from vbeye.report import build_html
from vbeye.scoring import CheckerResult, compute_score


GRADE_COLOR = {
    "A": "bold green", "B": "green", "C": "yellow",
    "D": "orange3",   "E": "red",   "F": "bold red",
}


@dataclass
class BatchResult:
    target: str
    slug: str
    score: int = 0
    grade: str = "F"
    findings_count: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    duration_sec: float = 0.0
    html_path: str | None = None
    docx_path: str | None = None
    json_path: str | None = None
    error: str | None = None


def normalize_target(line: str) -> str:
    t = line.strip()
    if not t or t.startswith("#"):
        return ""
    if "://" not in t:
        t = f"https://{t}"
    return t


def parse_targets_file(path: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        n = normalize_target(line)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _slug(target: str) -> str:
    p = urlparse(target)
    host = p.hostname or "target"
    return host.replace(".", "_")


def _scan_one(target: str, batch_dir: Path, opts: dict) -> BatchResult:
    slug = _slug(target)
    r = BatchResult(target=target, slug=slug)
    t0 = time.time()
    try:
        skip = set(opts.get("skip", []))
        timeout = opts.get("timeout", 15)
        checker_results: list[CheckerResult] = []
        for name, runner in (
            ("headers", headers_check.run),
            ("ssl",     ssl_check.run),
            ("source",  source_check.run),
        ):
            if name in skip:
                continue
            checker_results.append(runner(target, timeout=timeout))

        score, grade = compute_score(checker_results)
        r.score = score
        r.grade = grade

        counts: dict[str, int] = {}
        for cr in checker_results:
            for f in cr.findings:
                counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        r.findings_count = counts
        r.total_findings = sum(counts.values())

        if not opts.get("no_html", False):
            html_path = batch_dir / f"{slug}.html"
            html_path.write_text(build_html(target, checker_results), encoding="utf-8")
            r.html_path = str(html_path)

        if opts.get("json", False):
            json_path = batch_dir / f"{slug}.json"
            data = {
                "target": target, "score": score, "grade": grade,
                "results": [cr.to_dict() for cr in checker_results],
            }
            json_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            r.json_path = str(json_path)

        if opts.get("docx", False):
            cfg = opts["docx_cfg"]
            docx_path = batch_dir / f"{slug}.docx"
            build_docx(
                target=target,
                results=checker_results,
                output_path=str(docx_path),
                cfg=cfg,
                industry=opts.get("industry"),
                compliance=opts.get("compliance"),
                price_offer1=opts.get("price"),
                duration_offer1=opts.get("duration"),
                scan_source=opts.get("scan_source"),
            )
            r.docx_path = str(docx_path)
    except Exception as e:
        r.error = f"{type(e).__name__}: {e}"
    finally:
        r.duration_sec = time.time() - t0
    return r


def run_batch(targets: list[str], opts: dict, concurrency: int, console=None) -> tuple[list[BatchResult], Path]:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    batch_dir = Path.cwd() / "reports" / f"batch_{stamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    if console:
        console.print(f"[bold]Batch scan:[/] {len(targets)} target, concurrency={concurrency}")
        console.print(f"[dim]Output: {batch_dir}[/]\n")

    results: list[BatchResult] = []
    total = len(targets)
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        future_to_target = {pool.submit(_scan_one, t, batch_dir, opts): t for t in targets}
        for i, fut in enumerate(as_completed(future_to_target), 1):
            res = fut.result()
            results.append(res)
            if console:
                if res.error:
                    console.print(
                        f"  \\[{i:>3}/{total}] [red]✗[/] {res.target} "
                        f"[dim]({res.duration_sec:.1f}s)[/] — [red]{res.error}[/]"
                    )
                else:
                    color = GRADE_COLOR.get(res.grade, "white")
                    crit = res.findings_count.get("critical", 0)
                    high = res.findings_count.get("high", 0)
                    extras = ""
                    if crit:
                        extras += f"  [bold red]C:{crit}[/]"
                    if high:
                        extras += f"  [red]H:{high}[/]"
                    console.print(
                        f"  \\[{i:>3}/{total}] [{color}]{res.grade}[/] "
                        f"({res.score:>3}/100)  {res.target:<55} "
                        f"[dim]{res.total_findings:>2} finding, {res.duration_sec:>4.1f}s[/]{extras}"
                    )

    # Sort results by grade severity then by target name for predictable CSV order
    grade_rank = {"F": 0, "E": 1, "D": 2, "C": 3, "B": 4, "A": 5}
    results.sort(key=lambda r: (grade_rank.get(r.grade, 99), r.target))
    return results, batch_dir


def write_csv_summary(results: list[BatchResult], path: Path) -> None:
    columns = [
        "target", "grade", "score",
        "critical", "high", "medium", "low", "info",
        "total_findings", "duration_sec", "error", "html_path",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(columns)
        for r in results:
            w.writerow([
                r.target, r.grade, r.score,
                r.findings_count.get("critical", 0),
                r.findings_count.get("high", 0),
                r.findings_count.get("medium", 0),
                r.findings_count.get("low", 0),
                r.findings_count.get("info", 0),
                r.total_findings,
                round(r.duration_sec, 1),
                r.error or "",
                r.html_path or "",
            ])


def print_summary(results: list[BatchResult], console) -> None:
    by_grade: dict[str, int] = {}
    errors = 0
    for r in results:
        if r.error:
            errors += 1
        else:
            by_grade[r.grade] = by_grade.get(r.grade, 0) + 1

    console.print()
    console.print("[bold]Összesítés:[/]")
    for g in ("A", "B", "C", "D", "E", "F"):
        n = by_grade.get(g, 0)
        if n:
            color = GRADE_COLOR.get(g, "white")
            console.print(f"  [{color}]{g}[/]: {n}")
    if errors:
        console.print(f"  [red]hibás: {errors}[/]")
