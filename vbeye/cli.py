from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vbeye import __version__
from vbeye.batch import BatchItem, default_batch_dir, parse_targets_file, run_batch, write_csv_summary
from vbeye.engine import MODULES, ScanReport, normalize_target, scan, slug
from vbeye.output import AUTO, write_outputs
from vbeye.plugins import OutputPlugin, PluginError, load_plugins
from vbeye.scoring import SEVERITY_RANK, CheckerResult, Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
    Severity.OK: "green",
}

GRADE_STYLE = {
    "A": "bold green", "B": "green", "C": "yellow",
    "D": "orange3", "E": "red", "F": "bold red",
}

BANNER = r"""
██╗   ██╗██████╗ ███████╗██╗   ██╗███████╗
██║   ██║██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║██████╔╝█████╗   ╚████╔╝ █████╗
╚██╗ ██╔╝██╔══██╗██╔══╝    ╚██╔╝  ██╔══╝
 ╚████╔╝ ██████╔╝███████╗   ██║   ███████╗
  ╚═══╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝
"""

TAGLINE = "Passive Web Security Assessment"


def build_parser(plugins: Sequence[OutputPlugin] = ()) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vbeye",
        description=f"vbeye {__version__} - {TAGLINE}: HTTP security headers, TLS configuration and page source.",
        epilog="Only scan targets you are authorized to assess.",
    )
    parser.add_argument("target", nargs="?", help="target URL or hostname (https:// is assumed)")

    scan_group = parser.add_argument_group("scan options")
    scan_group.add_argument("--skip", nargs="+", default=[], choices=MODULES, metavar="MODULE",
                            help=f"modules to skip: {', '.join(MODULES)}")
    scan_group.add_argument("-t", "--timeout", type=int, default=15, metavar="SEC",
                            help="network timeout in seconds (default: 15)")
    scan_group.add_argument("-A", "--user-agent", metavar="UA", help="custom User-Agent header")

    out_group = parser.add_argument_group("output")
    out_group.add_argument("-o", "--output", metavar="FILE", help="HTML report path (single target)")
    out_group.add_argument("--output-dir", metavar="DIR", default="reports",
                           help="directory for generated reports (default: ./reports)")
    out_group.add_argument("--json", nargs="?", const=AUTO, metavar="FILE",
                           help="write JSON results (path optional)")
    out_group.add_argument("--no-html", action="store_true", help="do not write an HTML report")
    out_group.add_argument("-q", "--quiet", action="store_true", help="print only the result line and output paths")
    out_group.add_argument("--no-color", action="store_true", help="disable colored output")
    out_group.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="high",
                           help="exit with code 1 if a finding of this severity or higher exists (default: high)")

    batch_group = parser.add_argument_group("batch mode")
    batch_group.add_argument("-b", "--batch", metavar="FILE",
                             help="file with one target per line ('#' starts a comment)")
    batch_group.add_argument("-c", "--concurrency", type=int, default=4, metavar="N",
                             help="parallel scans in batch mode, 1-16 (default: 4)")
    batch_group.add_argument("--csv", metavar="FILE", help="batch summary CSV path (default: <batch dir>/summary.csv)")

    for plugin in plugins:
        plugin.add_arguments(parser)

    parser.add_argument("-V", "--version", action="version", version=f"vbeye {__version__}")
    return parser


def _exceeds(report: ScanReport, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_RANK[Severity(fail_on)]
    return any(
        SEVERITY_RANK[f.severity] >= threshold
        for r in report.results
        for f in r.findings
    )


def _print_banner(console: Console, subtitle: str) -> None:
    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(f"[bold]vbeye {__version__}[/] · {TAGLINE}")
    console.print(f"[dim]{subtitle}[/]")
    console.print("[yellow]Only scan targets you are authorized to assess.[/]\n")


def _print_module(console: Console, name: str, result: CheckerResult, elapsed: float) -> None:
    if result.error:
        console.print(f"  [red]✗[/] {name} ({elapsed:.1f}s) - {result.error}")
        return
    n = sum(1 for f in result.findings if f.severity != Severity.OK)
    console.print(f"  [green]✓[/] {name} ({elapsed:.1f}s) - {n} finding{'s' if n != 1 else ''}")


def _print_summary(console: Console, report: ScanReport) -> None:
    style = GRADE_STYLE.get(report.grade, "white")
    counts = report.severity_counts()
    text = Text()
    text.append("Score: ", style="bold")
    text.append(f"{report.score}/100  ", style=style)
    text.append("Grade: ", style="bold")
    text.append(f"{report.grade}\n", style=style)
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if counts.get(sev):
            text.append(f"  {sev.value}: ", style="bold")
            text.append(f"{counts[sev]}  ", style=SEVERITY_STYLE[sev])
    console.print(Panel(text, title=f"[bold]vbeye[/] · {report.target}", border_style=style))


def _print_findings(console: Console, report: ScanReport) -> None:
    for r in report.results:
        if r.error:
            console.print(f"\n[bold red]{r.name.upper()} error:[/] {r.error}")
            continue
        table = Table(title=r.name.upper(), expand=True)
        table.add_column("Severity", width=10)
        table.add_column("Finding")
        table.add_column("Check ID", style="dim")
        for f in r.findings:
            table.add_row(Text(f.severity.value.upper(), style=SEVERITY_STYLE[f.severity]), f.title, f.check_id)
        console.print(table)


def _run_single(args: argparse.Namespace, console: Console, plugins: Sequence[OutputPlugin]) -> int:
    target = normalize_target(args.target)
    if not args.quiet:
        _print_banner(console, f"Target: {target}")

    def on_module(name: str, result: CheckerResult, elapsed: float) -> None:
        if not args.quiet:
            _print_module(console, name, result, elapsed)

    report = scan(target, skip=args.skip, timeout=args.timeout, user_agent=args.user_agent, on_module=on_module)

    if args.quiet:
        console.print(f"{report.grade} {report.score}/100 {report.target}")
    else:
        console.print()
        _print_summary(console, report)
        _print_findings(console, report)

    stem = f"{slug(target)}_{time.strftime('%Y%m%d_%H%M%S')}"
    written = write_outputs(report, args, output_dir=Path(args.output_dir), stem=stem, plugins=plugins)
    for label, path in written.files:
        console.print(f"[bold green]{label}:[/] {path}")
    for err in written.errors:
        console.print(f"[bold red]Output error:[/] {err}")

    if written.errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if _exceeds(report, args.fail_on) else EXIT_OK


def _run_batch(args: argparse.Namespace, console: Console, plugins: Sequence[OutputPlugin]) -> int:
    targets_path = Path(args.batch)
    if not targets_path.is_file():
        console.print(f"[bold red]Error:[/] targets file not found: {targets_path}")
        return EXIT_ERROR
    targets = parse_targets_file(targets_path)
    if not targets:
        console.print(f"[bold red]Error:[/] no targets in {targets_path}")
        return EXIT_ERROR

    batch_dir = default_batch_dir(Path(args.output_dir))
    if not args.quiet:
        _print_banner(console, f"Batch: {len(targets)} targets, concurrency {args.concurrency}")
        console.print(f"[dim]Output: {batch_dir}[/]\n")

    def on_done(i: int, total: int, item: BatchItem) -> None:
        if args.quiet:
            return
        prefix = f"  \\[{i:>3}/{total}]"
        if item.report is None:
            console.print(f"{prefix} [red]✗[/] {item.target} - [red]{item.error}[/]")
            return
        style = GRADE_STYLE.get(item.grade, "white")
        counts = item.report.severity_counts()
        extras = ""
        if counts.get(Severity.CRITICAL):
            extras += f"  [bold red]C:{counts[Severity.CRITICAL]}[/]"
        if counts.get(Severity.HIGH):
            extras += f"  [red]H:{counts[Severity.HIGH]}[/]"
        if item.error:
            extras += f"  [red]{item.error}[/]"
        console.print(
            f"{prefix} [{style}]{item.grade}[/] ({item.score:>3}/100)  {item.target:<50} "
            f"[dim]{item.report.duration:>5.1f}s[/]{extras}"
        )

    items = run_batch(targets, args, batch_dir, plugins, on_done=on_done)

    csv_path = Path(args.csv) if args.csv else batch_dir / "summary.csv"
    write_csv_summary(items, csv_path)

    if args.quiet:
        for it in items:
            console.print(f"{it.grade} {'' if it.score is None else it.score} {it.target}")
    else:
        console.print("\n[bold]Summary:[/]")
        by_grade: dict[str, int] = {}
        for it in items:
            by_grade[it.grade] = by_grade.get(it.grade, 0) + 1
        for g in ("A", "B", "C", "D", "E", "F", "-"):
            if by_grade.get(g):
                label = "failed" if g == "-" else g
                console.print(f"  [{GRADE_STYLE.get(g, 'red')}]{label}[/]: {by_grade[g]}")
    console.print(f"[bold green]CSV:[/] {csv_path}")

    if any(it.report is None or it.error for it in items):
        return EXIT_ERROR
    if any(_exceeds(it.report, args.fail_on) for it in items):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    plugins = load_plugins()
    parser = build_parser(plugins)
    args = parser.parse_args(argv)

    if args.batch and args.target:
        parser.error("a positional target and --batch are mutually exclusive")
    if not args.batch and not args.target:
        parser.print_help()
        return EXIT_ERROR
    if not 1 <= args.concurrency <= 16:
        parser.error("--concurrency must be between 1 and 16")
    if args.timeout < 1:
        parser.error("--timeout must be a positive integer")
    if args.batch and args.output:
        parser.error("-o/--output applies to single-target scans; use --output-dir with --batch")

    console = Console(no_color=args.no_color, highlight=False)

    active = [p for p in plugins if p.enabled(args)]
    for plugin in active:
        try:
            plugin.prepare(args)
        except PluginError as e:
            console.print(f"[bold red]{plugin.name} error:[/] {e}")
            return EXIT_ERROR

    try:
        if args.batch:
            return _run_batch(args, console, active)
        return _run_single(args, console, active)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
