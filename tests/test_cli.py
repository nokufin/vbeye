from __future__ import annotations

import csv
import json

import pytest

from vbeye import batch, cli
from vbeye.engine import ScanReport
from vbeye.scoring import CheckerResult, Finding, Severity


def fake_report(target: str, severity: Severity | None = None) -> ScanReport:
    findings = [Finding("headers.x", "x", severity, "d")] if severity else []
    return ScanReport(target=target, results=[CheckerResult("headers", findings)])


@pytest.fixture
def stub_scan(monkeypatch):
    def install(severity=None, per_target=None):
        def scan(target, **kwargs):
            sev = (per_target or {}).get(target, severity)
            return fake_report(target, sev)
        monkeypatch.setattr(cli, "scan", scan)
        monkeypatch.setattr(batch, "scan", scan)
    monkeypatch.setattr(cli, "load_plugins", lambda: [])
    return install


def run(args, tmp_path):
    return cli.main([*args, "--output-dir", str(tmp_path), "--no-color", "-q"])


def test_no_target_prints_help(stub_scan, tmp_path, capsys):
    stub_scan()
    assert cli.main([]) == cli.EXIT_ERROR


def test_target_and_batch_conflict(stub_scan, tmp_path):
    stub_scan()
    with pytest.raises(SystemExit) as exc:
        cli.main(["example.com", "--batch", "t.txt"])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    ("severity", "fail_on", "code"),
    [(None, "high", 0), (Severity.MEDIUM, "high", 0), (Severity.HIGH, "high", 1),
     (Severity.CRITICAL, "high", 1), (Severity.MEDIUM, "medium", 1), (Severity.CRITICAL, "never", 0),
     (Severity.LOW, "low", 1), (Severity.INFO, "low", 0)],
)
def test_exit_codes(stub_scan, tmp_path, severity, fail_on, code):
    stub_scan(severity)
    assert run(["example.com", "--fail-on", fail_on], tmp_path) == code


def test_single_writes_html_and_json(stub_scan, tmp_path):
    stub_scan()
    out_json = tmp_path / "out.json"
    out_html = tmp_path / "out.html"
    assert run(["example.com", "-o", str(out_html), "--json", str(out_json)], tmp_path) == 0
    assert json.loads(out_json.read_text(encoding="utf-8"))["target"] == "https://example.com"
    assert out_html.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_single_no_html(stub_scan, tmp_path):
    stub_scan()
    assert run(["example.com", "--no-html"], tmp_path) == 0
    assert not list(tmp_path.glob("*.html"))


def test_batch(stub_scan, tmp_path):
    stub_scan(per_target={"https://bad.example": Severity.CRITICAL})
    targets = tmp_path / "targets.txt"
    targets.write_text("# comment\ngood.example\n\nbad.example  # inline\ngood.example\n", encoding="utf-8")
    code = run(["--batch", str(targets), "--json"], tmp_path)
    assert code == cli.EXIT_FINDINGS

    batch_dir = next(tmp_path.glob("batch_*"))
    rows = list(csv.DictReader((batch_dir / "summary.csv").open(encoding="utf-8")))
    assert [r["target"] for r in rows] == ["https://bad.example", "https://good.example"]
    assert rows[0]["critical"] == "1"
    assert (batch_dir / "good_example.json").exists()
    assert (batch_dir / "bad_example.html").exists()


def test_batch_missing_file(stub_scan, tmp_path):
    stub_scan()
    assert run(["--batch", str(tmp_path / "nope.txt")], tmp_path) == cli.EXIT_ERROR


def test_batch_rejects_output_flag(stub_scan, tmp_path):
    stub_scan()
    with pytest.raises(SystemExit):
        cli.main(["--batch", "t.txt", "-o", "x.html"])


def test_plugin_is_invoked(monkeypatch, tmp_path):
    class Plugin:
        name = "demo"

        def add_arguments(self, parser):
            parser.add_argument("--demo", action="store_true")

        def enabled(self, args):
            return args.demo

        def prepare(self, args):
            self.prepared = True

        def write(self, report, args, output_dir, stem):
            path = output_dir / f"{stem}.demo"
            path.write_text(report.target, encoding="utf-8")
            return path

    plugin = Plugin()
    monkeypatch.setattr(cli, "load_plugins", lambda: [plugin])
    monkeypatch.setattr(cli, "scan", lambda target, **kw: fake_report(target))
    assert run(["example.com", "--demo", "--no-html"], tmp_path) == 0
    assert plugin.prepared
    assert next(tmp_path.glob("*.demo")).read_text(encoding="utf-8") == "https://example.com"
