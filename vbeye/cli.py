from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vbeye import __version__
from vbeye.batch import parse_targets_file, print_summary, run_batch, write_csv_summary
from vbeye.checkers import headers as headers_check
from vbeye.checkers import ssl as ssl_check
from vbeye.checkers import source as source_check
from vbeye.config import load as load_config
from vbeye.docx_report import build as build_docx
from vbeye.report import build_html
from vbeye.scoring import CheckerResult, Severity, compute_score


SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
    Severity.OK: "green",
}


BANNER = r"""
██╗   ██╗██████╗ ███████╗██╗   ██╗███████╗
██║   ██║██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝
██║   ██║██████╔╝█████╗   ╚████╔╝ █████╗
╚██╗ ██╔╝██╔══██╗██╔══╝    ╚██╔╝  ██╔══╝
 ╚████╔╝ ██████╔╝███████╗   ██║   ███████╗
  ╚═══╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝
"""

AUTHOR = "theEreb0x"
SUBTITLE = "Passive Web Security Assessment Tool"


def _print_banner(console: Console, target: str) -> None:
    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(f"[bold]VBEye v{__version__}[/]")
    console.print(f"[dim]{SUBTITLE}[/]\n")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    console.print(rf"[green]\[INFO][/] Author: [bold]{AUTHOR}[/]")
    console.print(r"[green]\[INFO][/] Mode: [bold]Passive Recon[/]")
    console.print(rf"[green]\[INFO][/] Target: [cyan]{target}[/]")
    console.print(rf"[green]\[INFO][/] Timestamp: [bold]{ts}[/]")
    console.print()
    console.print(r"[yellow]\[WARNING][/] Authorized testing only.")
    console.print(r"[yellow]\[WARNING][/] The author is not responsible for misuse.")
    console.print()
    console.print("[dim]" + "-" * 50 + "[/]")
    console.print(r"[green bold]\[+][/] Starting reconnaissance...")
    console.print()


def _normalize_url(target: str) -> str:
    if "://" not in target:
        return f"https://{target}"
    return target


def _slug(target: str) -> str:
    p = urlparse(_normalize_url(target))
    host = p.hostname or "target"
    return host.replace(".", "_")


def _print_summary(console: Console, target: str, results: list[CheckerResult]) -> None:
    score, grade = compute_score(results)
    counts: dict[Severity, int] = {}
    for r in results:
        for f in r.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

    color = {
        "A": "bold green", "B": "green", "C": "yellow",
        "D": "orange3", "E": "red", "F": "bold red",
    }.get(grade, "white")

    summary = Text()
    summary.append(f"Score: ", style="bold")
    summary.append(f"{score}/100  ", style=color)
    summary.append(f"Grade: ", style="bold")
    summary.append(f"{grade}\n", style=color)
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        if n:
            summary.append(f"  {sev.value}: ", style="bold")
            summary.append(f"{n}  ", style=SEVERITY_COLOR[sev])

    console.print(Panel(summary, title=f"[bold]vbeye[/] · {target}", border_style=color))


def _print_findings(console: Console, results: list[CheckerResult]) -> None:
    for r in results:
        if r.error:
            console.print(f"\n[bold red]{r.name.upper()} hiba:[/] {r.error}")
            continue
        table = Table(title=f"{r.name.upper()}", show_lines=False, expand=True)
        table.add_column("Severity", width=10)
        table.add_column("Title")
        table.add_column("Check ID", style="dim")
        for f in r.findings:
            table.add_row(
                Text(f.severity.value.upper(), style=SEVERITY_COLOR[f.severity]),
                f.title,
                f.check_id,
            )
        console.print(table)


def _print_batch_banner(console: Console) -> None:
    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(f"[bold]VBEye v{__version__}[/] · batch mode")
    console.print(f"[dim]{SUBTITLE}[/]\n")


def _run_batch_mode(args, console: Console) -> int:
    targets_path = Path(args.batch)
    if not targets_path.exists():
        console.print(f"[bold red]Hiba:[/] Targets fájl nem található: {targets_path}")
        return 1

    targets = parse_targets_file(targets_path)
    if not targets:
        console.print(f"[bold red]Hiba:[/] {targets_path} üres vagy csak komment.")
        return 1

    if args.concurrency < 1 or args.concurrency > 16:
        console.print(f"[bold red]Hiba:[/] --concurrency 1 és 16 közé kell essen (kaptam: {args.concurrency}).")
        return 1

    _print_batch_banner(console)

    docx_cfg = None
    if args.docx is not None:
        try:
            docx_cfg = load_config(args.config)
        except FileNotFoundError as e:
            console.print(f"[bold red]Config hiba:[/] {e}")
            return 1
        if docx_cfg.source_path:
            console.print(f"[dim]config: {docx_cfg.source_path}[/]")

    opts = {
        "skip": args.skip,
        "timeout": args.timeout,
        "no_html": args.no_html,
        "json": args.batch_json,
        "docx": args.docx is not None,
        "docx_cfg": docx_cfg,
        "industry": args.industry,
        "compliance": args.compliance,
        "price": args.price,
        "duration": args.duration,
        "scan_source": args.scan_source,
    }

    results, batch_dir = run_batch(targets, opts, args.concurrency, console=console)

    csv_path = Path(args.batch_csv) if args.batch_csv else batch_dir / "summary.csv"
    write_csv_summary(results, csv_path)

    print_summary(results, console)
    console.print(f"\n[bold green]CSV summary:[/] {csv_path}")
    console.print(f"[bold green]Reports dir:[/] {batch_dir}")

    # Exit code: 2 ha bármelyik target F vagy E, 0 egyébként
    has_severe = any(r.grade in ("E", "F") for r in results if not r.error)
    return 2 if has_severe else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vbeye",
        description="Nyilvános website security audit (headers, TLS, source).",
    )
    parser.add_argument("target", nargs="?", help="URL vagy hostnév (pl. example.com vagy https://example.com). Batch módban hagyd üresen és add meg --batch-tel.")
    parser.add_argument("-o", "--output", help="HTML report kimeneti útvonal (default: ./reports/<host>_<ts>.html)")
    parser.add_argument("--json", dest="json_out", help="JSON eredmény ki külön fájlba (single módban útvonal; batch módban flag formájában igaz/hamis)")
    parser.add_argument("--no-html", action="store_true", help="Ne generáljon HTML reportot")
    parser.add_argument("--skip", nargs="+", default=[], choices=["headers", "ssl", "source"], help="Modulok átugrása")
    parser.add_argument("--timeout", type=int, default=15, help="Per-checker timeout sec (default: 15)")

    # Batch mód
    batch_group = parser.add_argument_group("Batch scan (több target egyszerre)")
    batch_group.add_argument("--batch", help="Targets fájl (egy domain/URL soronként, # komment OK). Inkompatibilis a pozicionális target-tel.")
    batch_group.add_argument("--concurrency", type=int, default=4, help="Párhuzamos scan-ek száma (default: 4, max ajánlott: 8)")
    batch_group.add_argument("--batch-csv", help="CSV summary kimenet útvonala (default: batch dir / summary.csv)")
    batch_group.add_argument("--batch-json", action="store_true", help="Batch módban minden target-hez JSON-t is írjon")

    # DOCX deliverable
    docx_group = parser.add_argument_group("DOCX kimenet (üzleti deliverable)")
    docx_group.add_argument("--docx", nargs="?", const="__auto__", default=None,
                            help="Generálj DOCX riportot. Útvonal opcionális (default: ./reports/<host>_<ts>.docx)")
    docx_group.add_argument("--config", help="Config fájl útvonala (default: ./vbeye.toml vagy ~/.config/vbeye/config.toml)")
    docx_group.add_argument("--industry", help="Iparág a vezetői összefoglalóhoz (pl. 'gyártó vállalat', 'közintézmény')")
    docx_group.add_argument("--compliance", help="Vonatkozó megfelelőségi keret (pl. 'GDPR és NIS2', 'PCI-DSS')")
    docx_group.add_argument("--price", help="Ajánlat 1 irányár (üres string a kihagyáshoz)")
    docx_group.add_argument("--duration", help="Ajánlat 1 időtartam")
    docx_group.add_argument("--scan-source", help="Scan forrás megjelölése a táblázatban (default: 'vbeye')")

    parser.add_argument("-v", "--version", action="version", version=f"vbeye {__version__}")

    args = parser.parse_args()
    console = Console()

    # ---- Mode selection ----
    if args.batch and args.target:
        console.print("[bold red]Hiba:[/] --batch és pozicionális target együtt nem adható meg.")
        return 1
    if not args.batch and not args.target:
        parser.print_help()
        return 1

    if args.batch:
        return _run_batch_mode(args, console)

    target = _normalize_url(args.target)

    _print_banner(console, target)

    results: list[CheckerResult] = []

    modules = [
        ("headers", headers_check.run),
        ("ssl", ssl_check.run),
        ("source", source_check.run),
    ]

    for name, runner in modules:
        if name in args.skip:
            console.print(f"  [dim]skip: {name}[/]")
            continue
        with console.status(f"[bold]Running {name}...[/]"):
            t0 = time.time()
            r = runner(target, timeout=args.timeout)
            dt = time.time() - t0
        console.print(f"  [green]✓[/] {name} ({dt:.1f}s) — {len(r.findings)} finding{'s' if len(r.findings) != 1 else ''}")
        results.append(r)

    console.print()
    _print_summary(console, target, results)
    _print_findings(console, results)

    score, grade = compute_score(results)

    if not args.no_html:
        output = args.output
        if not output:
            reports_dir = Path.cwd() / "reports"
            reports_dir.mkdir(exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            output = str(reports_dir / f"{_slug(target)}_{stamp}.html")
        Path(output).write_text(build_html(target, results), encoding="utf-8")
        console.print(f"\n[bold green]HTML report:[/] {output}")

    if args.json_out:
        data = {
            "target": target,
            "score": score,
            "grade": grade,
            "results": [r.to_dict() for r in results],
        }
        Path(args.json_out).write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        console.print(f"[bold green]JSON:[/] {args.json_out}")

    if args.docx is not None:
        try:
            cfg = load_config(args.config)
        except FileNotFoundError as e:
            console.print(f"[bold red]Config hiba:[/] {e}")
            return 1
        if cfg.source_path:
            console.print(f"  [dim]config: {cfg.source_path}[/]")

        docx_path = args.docx
        if docx_path == "__auto__":
            reports_dir = Path.cwd() / "reports"
            reports_dir.mkdir(exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            docx_path = str(reports_dir / f"{_slug(target)}_{stamp}.docx")

        out = build_docx(
            target=target,
            results=results,
            output_path=docx_path,
            cfg=cfg,
            industry=args.industry,
            compliance=args.compliance,
            price_offer1=args.price,
            duration_offer1=args.duration,
            scan_source=args.scan_source,
        )
        console.print(f"[bold green]DOCX deliverable:[/] {out}")

    # Exit code: 0 jó/közepes, 2 ha kritikus/magas finding van
    has_high = any(
        f.severity in (Severity.HIGH, Severity.CRITICAL)
        for r in results
        for f in r.findings
    )
    return 2 if has_high else 0


if __name__ == "__main__":
    sys.exit(main())
