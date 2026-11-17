from __future__ import annotations

import json

import pytest

from vbeye import engine
from vbeye.net import Page
from vbeye.output import write_json
from vbeye.report import build_html
from vbeye.scoring import CheckerResult, Finding, Severity


@pytest.fixture
def fake_checkers(monkeypatch):
    calls = []

    def make(name, findings=(), raises=None):
        def run(ctx):
            calls.append((name, ctx))
            if raises:
                raise raises
            return CheckerResult(name, list(findings))
        return run

    def install(**overrides):
        checkers = {name: make(name) for name in engine.MODULES}
        checkers.update({k: make(k, **v) for k, v in overrides.items()})
        monkeypatch.setattr(engine, "CHECKERS", checkers)
        return calls

    monkeypatch.setattr(engine, "fetch", lambda url, timeout, ua=None: Page(requested_url=url))
    return install


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("example.com", "https://example.com"), ("http://example.com", "http://example.com"),
     ("  https://a.b/x ", "https://a.b/x")],
)
def test_normalize_target(raw, expected):
    assert engine.normalize_target(raw) == expected


def test_slug():
    assert engine.slug("https://www.example.co.uk:8443/x") == "www_example_co_uk"


def test_scan_runs_all_modules_with_shared_context(fake_checkers):
    calls = fake_checkers()
    report = engine.scan("example.com")
    assert [r.name for r in report.results] == list(engine.MODULES)
    contexts = {id(ctx) for _, ctx in calls}
    assert len(contexts) == 1
    assert calls[0][1].url == "https://example.com"


def test_scan_skip(fake_checkers):
    fake_checkers()
    report = engine.scan("example.com", skip=["ssl"])
    assert [r.name for r in report.results] == ["headers", "source"]


def test_checker_exception_becomes_error(fake_checkers):
    fake_checkers(ssl={"raises": RuntimeError("boom")})
    report = engine.scan("example.com")
    ssl_result = next(r for r in report.results if r.name == "ssl")
    assert ssl_result.error == "Internal error: RuntimeError: boom"


def test_on_module_callback(fake_checkers):
    fake_checkers()
    seen = []
    engine.scan("example.com", on_module=lambda name, result, elapsed: seen.append(name))
    assert seen == list(engine.MODULES)


def test_report_serialization(fake_checkers, tmp_path):
    fake_checkers(headers={"findings": [Finding("headers.csp.missing", "<script>", Severity.MEDIUM, "d")]})
    report = engine.scan("example.com")

    data = json.loads(write_json(report, tmp_path / "r.json").read_text(encoding="utf-8"))
    assert data["tool"] == "vbeye"
    assert data["target"] == "https://example.com"
    assert data["score"] == report.score
    assert data["results"][0]["findings"][0]["severity"] == "medium"

    page = build_html(report)
    assert "&lt;script&gt;" in page
    assert "<script>" not in page
    assert 'lang="en"' in page
