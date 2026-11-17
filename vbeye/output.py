from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from vbeye.engine import ScanReport
from vbeye.plugins import OutputPlugin
from vbeye.report import build_html

AUTO = "__auto__"


@dataclass
class WrittenOutputs:
    files: list[tuple[str, Path]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def write_json(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return path


def write_html(report: ScanReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_html(report), encoding="utf-8")
    return path


def write_outputs(
    report: ScanReport,
    args: argparse.Namespace,
    *,
    output_dir: Path,
    stem: str,
    plugins: Sequence[OutputPlugin] = (),
    explicit_paths: bool = True,
) -> WrittenOutputs:
    out = WrittenOutputs()

    if not args.no_html:
        html_path = Path(args.output) if explicit_paths and args.output else output_dir / f"{stem}.html"
        out.files.append(("HTML", write_html(report, html_path)))

    if args.json is not None:
        json_path = Path(args.json) if explicit_paths and args.json != AUTO else output_dir / f"{stem}.json"
        out.files.append(("JSON", write_json(report, json_path)))

    for plugin in plugins:
        if not plugin.enabled(args):
            continue
        try:
            path = plugin.write(report, args, output_dir, stem)
        except Exception as e:
            out.errors.append(f"{plugin.name}: {type(e).__name__}: {e}")
            continue
        if path:
            out.files.append((plugin.name.upper(), Path(path)))

    return out
