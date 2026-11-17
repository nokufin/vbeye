from __future__ import annotations

import argparse
import csv
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from vbeye.engine import ScanReport, normalize_target, scan, slug
from vbeye.output import write_outputs
from vbeye.plugins import OutputPlugin

GRADE_RANK = {"F": 0, "E": 1, "D": 2, "C": 3, "B": 4, "A": 5}

CSV_COLUMNS = (
    "target", "grade", "score",
    "critical", "high", "medium", "low", "info",
    "total_findings", "duration_sec", "error", "outputs",
)


@dataclass
class BatchItem:
    target: str
    report: ScanReport | None = None
    outputs: list[tuple[str, Path]] = field(default_factory=list)
    error: str | None = None

    @property
    def grade(self) -> str:
        return self.report.grade if self.report else "-"

    @property
    def score(self) -> int | None:
        return self.report.score if self.report else None


def parse_targets_file(path: Path) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        t = normalize_target(line)
        if t not in seen:
            seen.add(t)
            targets.append(t)
    return targets


def _scan_one(
    target: str,
    args: argparse.Namespace,
    batch_dir: Path,
    plugins: Sequence[OutputPlugin],
) -> BatchItem:
    item = BatchItem(target=target)
    try:
        item.report = scan(target, skip=args.skip, timeout=args.timeout, user_agent=args.user_agent)
        written = write_outputs(
            item.report, args,
            output_dir=batch_dir, stem=slug(target), plugins=plugins, explicit_paths=False,
        )
        item.outputs = written.files
        if written.errors:
            item.error = "; ".join(written.errors)
    except Exception as e:
        item.error = f"{type(e).__name__}: {e}"
    return item


def run_batch(
    targets: Sequence[str],
    args: argparse.Namespace,
    batch_dir: Path,
    plugins: Sequence[OutputPlugin] = (),
    on_done: Callable[[int, int, BatchItem], None] | None = None,
) -> list[BatchItem]:
    batch_dir.mkdir(parents=True, exist_ok=True)
    items: list[BatchItem] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(_scan_one, t, args, batch_dir, plugins) for t in targets]
        for i, fut in enumerate(as_completed(futures), 1):
            item = fut.result()
            items.append(item)
            if on_done:
                on_done(i, len(targets), item)
    items.sort(key=lambda it: (GRADE_RANK.get(it.grade, 99), it.target))
    return items


def default_batch_dir(base: Path) -> Path:
    return base / f"batch_{time.strftime('%Y%m%d_%H%M%S')}"


def write_csv_summary(items: Sequence[BatchItem], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)
        for it in items:
            counts = {s.value: n for s, n in it.report.severity_counts().items()} if it.report else {}
            w.writerow([
                it.target,
                it.grade,
                "" if it.score is None else it.score,
                counts.get("critical", 0),
                counts.get("high", 0),
                counts.get("medium", 0),
                counts.get("low", 0),
                counts.get("info", 0),
                sum(n for k, n in counts.items() if k != "ok"),
                round(it.report.duration, 1) if it.report else "",
                it.error or "",
                ";".join(str(p) for _, p in it.outputs),
            ])
