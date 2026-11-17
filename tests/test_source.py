from __future__ import annotations

import base64
import json

import pytest
from conftest import make_ctx, make_response

from vbeye.checkers import source
from vbeye.scoring import Confidence, Severity


def scan(body: str, url: str = "https://www.example.com/", **kwargs):
    resp = make_response(url, body=body, **kwargs)
    return source.run(make_ctx(url, response=resp))


def ids(result) -> set[str]:
    return {f.check_id for f in result.findings}


def finding(result, check_id: str):
    matches = [f for f in result.findings if f.check_id == check_id]
    assert matches, f"{check_id} not in {ids(result)}"
    return matches[0]


def make_jwt(payload: dict) -> str:
    def enc(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc(payload)}.c2lnbmF0dXJlc2lnbmF0dXJl"


def test_page_error_passthrough():
    ctx = make_ctx(error="HTTP request failed: timeout")
    ctx.page.blocked_by = "datadome.co"
    r = source.run(ctx)
    assert r.error == "HTTP request failed: timeout"
    assert r.meta["blocked_by"] == "datadome.co"
    assert r.findings == []


def test_missing_response_is_error():
    r = source.run(make_ctx())
    assert r.error


def test_clean_page_reports_ok():
    r = scan("<html><head><title>x</title></head><body><p>hi</p></body></html>")
    assert ids(r) == {"source.ok"}


def test_mixed_content_script_and_srcset():
    body = (
        '<script src="http://cdn.example.net/a.js"></script>'
        '<img srcset="https://a.example.com/1.png 1x, http://b.example.com/2.png 2x">'
    )
    f = finding(scan(body), "source.mixed_content")
    assert f.severity == Severity.HIGH
    assert "http://cdn.example.net/a.js" in f.evidence
    assert "http://b.example.com/2.png" in f.evidence


def test_mixed_content_ignored_on_http_page():
    r = scan('<script src="http://cdn.example.net/a.js"></script>', url="http://www.example.com/")
    assert "source.mixed_content" not in ids(r)


@pytest.mark.parametrize("rel", ["canonical", "alternate", "dns-prefetch", "preconnect", "shortlink"])
def test_non_resource_links_are_not_mixed_content(rel):
    r = scan(f'<link rel="{rel}" href="http://www.example.com/page">')
    assert "source.mixed_content" not in ids(r)


@pytest.mark.parametrize("rel", ["stylesheet", "icon", "shortcut icon", "preload", "manifest"])
def test_resource_links_are_mixed_content(rel):
    r = scan(f'<link rel="{rel}" href="http://www.example.com/asset">')
    assert "source.mixed_content" in ids(r)


def test_protocol_relative_is_low_strong_indicator():
    f = finding(scan('<script src="//cdn.example.net/a.js" integrity="sha384-x"></script>'),
                "source.mixed_content.protocol_relative")
    assert f.severity == Severity.LOW
    assert f.confidence == Confidence.STRONG_INDICATOR


def test_protocol_relative_preconnect_ignored():
    r = scan('<link rel="preconnect" href="//fonts.gstatic.com">')
    assert "source.mixed_content.protocol_relative" not in ids(r)


def test_sri_third_party_script_flagged():
    f = finding(scan('<script src="https://cdn.thirdparty.net/lib.js"></script>'), "source.sri.missing")
    assert f.severity == Severity.MEDIUM


def test_sri_same_org_subdomain_not_flagged():
    r = scan('<script src="https://static.example.com/app.js"></script>')
    assert "source.sri.missing" not in ids(r)


def test_sri_present_not_flagged():
    r = scan('<script src="https://cdn.thirdparty.net/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>')
    assert "source.sri.missing" not in ids(r)


def test_sri_third_party_stylesheet_flagged_but_google_fonts_exempt():
    r = scan('<link rel="stylesheet" href="https://cdn.thirdparty.net/x.css">')
    assert "source.sri.missing" in ids(r)
    r = scan('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">')
    assert "source.sri.missing" not in ids(r)


def test_sri_ignores_non_resource_links():
    r = scan('<link rel="preconnect" href="https://cdn.thirdparty.net">'
             '<link rel="canonical" href="https://other.org/page">')
    assert "source.sri.missing" not in ids(r)


def test_form_http_action():
    f = finding(scan('<form action="http://www.example.com/login" method="post"></form>'),
                "source.form.http_action")
    assert f.severity == Severity.HIGH


def test_password_on_http_is_single_critical():
    body = ('<form method="post"><input type="password" name="p"></form>'
            '<form method="post"><input type="password" name="q"></form>')
    r = scan(body, url="http://www.example.com/")
    pw = [f for f in r.findings if f.check_id == "source.form.password_on_http"]
    assert len(pw) == 1
    assert pw[0].severity == Severity.CRITICAL
    http_action = [f for f in r.findings if f.check_id == "source.form.http_action"]
    assert len(http_action) == 1


def test_password_on_https_not_flagged():
    r = scan('<form method="post" action="/login"><input type="password"></form>')
    assert "source.form.password_on_http" not in ids(r)
    assert "source.form.http_action" not in ids(r)


def test_autocomplete_off():
    r = scan('<form action="/l"><input type="password" autocomplete="off"></form>')
    assert finding(r, "source.form.autocomplete_off").severity == Severity.INFO


def test_inline_handlers_and_scripts():
    r = scan('<button onclick="go()">x</button><script>var a = 1;</script><script src="/a.js"></script>')
    assert finding(r, "source.inline_handlers").severity == Severity.LOW
    inline = finding(r, "source.inline_scripts")
    assert inline.title.endswith("(1)")


def test_comment_leak_detected():
    f = finding(scan("<!-- TODO: remove debug login admin/admin -->"), "source.comments.leak")
    assert f.confidence == Confidence.REQUIRES_MANUAL_VALIDATION


@pytest.mark.parametrize("comment", [
    "<!-- Google Tag Manager TODO: something -->",
    "<!-- password manager friendly -->",
    "<!-- Page generated in 0.12 seconds -->",
    "<!--[if lt IE 9]><script src='x'></script><![endif]-->",
])
def test_comment_noise_ignored(comment):
    assert "source.comments.leak" not in ids(scan(comment))


def test_aws_key_is_exposed_secret():
    f = finding(scan("<script>var k='AKIAABCDEFGHIJKLMNOP';</script>"), "source.secret.exposed")
    assert f.severity == Severity.CRITICAL
    assert f.confidence == Confidence.VERIFIED


def test_private_key_block_is_exposed_secret():
    r = scan("<pre>-----BEGIN RSA PRIVATE KEY-----\nMIIE...</pre>")
    assert "source.secret.exposed" in ids(r)


@pytest.mark.parametrize("value", [
    "your_api_key_goes_here_please",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
])
def test_generic_secret_negatives(value):
    r = scan(f"<script>var cfg = {{api_key: '{value}'}};</script>")
    assert "source.secret.generic_hint" not in ids(r)


def test_generic_secret_high_entropy_hint():
    r = scan("<script>var cfg = {api_key: 'q8Zr3Kd9XvLm2Pw7TbN4Hs6Yc1Fg5Ju0'};</script>")
    f = finding(r, "source.secret.generic_hint")
    assert f.confidence == Confidence.REQUIRES_MANUAL_VALIDATION


def test_jwt_with_secret_claims_is_critical():
    jwt = make_jwt({"sub": "svc", "client_secret": "abc123"})
    r = scan(f"<script>var t='{jwt}';</script>")
    assert "source.secret.exposed" in ids(r)
    assert "source.secret.jwt_hint" not in ids(r)


def test_client_side_jwt_is_skipped():
    jwt = make_jwt({"guest_uuid": "1234-5678", "iat": 1700000000})
    r = scan(f"<script>var t='{jwt}';</script>")
    assert not ids(r) & {"source.secret.exposed", "source.secret.jwt_hint"}


def test_ambiguous_jwt_is_hint():
    jwt = make_jwt({"sub": "user-42", "role": "member"})
    f = finding(scan(f"<script>var t='{jwt}';</script>"), "source.secret.jwt_hint")
    assert f.confidence == Confidence.REQUIRES_MANUAL_VALIDATION


def test_google_api_key_hint():
    key = "AIza" + "S" * 35
    f = finding(scan(f"<script>var k='{key}';</script>"), "source.secret.google_api_key_hint")
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.REQUIRES_MANUAL_VALIDATION


@pytest.mark.parametrize("src,vulnerable", [
    ("https://code.jquery.com/jquery-3.4.1.min.js", True),
    ("https://code.jquery.com/jquery-3.5.0.min.js", False),
    ("https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js", True),
    ("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js", False),
    ("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.4.0/js/bootstrap.min.js", True),
    ("https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.4.1/js/bootstrap.min.js", False),
    ("https://cdn.jsdelivr.net/npm/bootstrap@4.3.0/dist/js/bootstrap.min.js", True),
    ("https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js", False),
    ("https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js", False),
    ("https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js", True),
    ("https://cdnjs.cloudflare.com/ajax/libs/jquery-ui/1.12.1/jquery-ui.min.js", False),
    ("https://www.example.com/js/jquery-migrate-1.4.1.min.js", False),
    ("https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.9.0/js/bootstrap-datepicker.min.js", False),
    ("https://www.example.com/wp-includes/js/jquery/jquery.min.js?ver=3.4.1", True),
    ("https://www.example.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1", False),
    ("https://www.example.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=1.4.1", False),
])
def test_library_detection(src, vulnerable):
    r = scan(f'<script src="{src}" integrity="sha384-x"></script>')
    assert ("source.lib.outdated" in ids(r)) is vulnerable


def test_library_detection_wp_stylesheet():
    r = scan('<link rel="stylesheet" href="/wp-content/themes/t/css/bootstrap.min.css?ver=3.3.7">')
    f = finding(r, "source.lib.outdated")
    assert "bootstrap 3.3.7" in f.evidence


@pytest.mark.parametrize("version,expected", [
    ("3.4.1", None),
    ("3.4.0", "CVE-2019-8331"),
    ("4.1.1", "CVE-2018-14040"),
    ("4.3.0", "CVE-2019-8331"),
    ("4.3.1", None),
])
def test_bootstrap_advisory_boundaries(version, expected):
    advisory = source._library_advisory("bootstrap", version)
    if expected is None:
        assert advisory is None
    else:
        assert expected in advisory


def test_jquery_advisory_boundary():
    assert source._library_advisory("jquery", "3.5.0") is None
    assert "CVE-2020-11022" in source._library_advisory("jquery", "3.4.1")
    assert "CVE-2015-9251" in source._library_advisory("jquery", "2.2.4")


def test_stale_analytics():
    f = finding(scan("<script>ga('create', 'UA-1234567-1', 'auto');</script>"), "source.tech.stale_analytics")
    assert f.severity == Severity.LOW


def test_csrf_hint_without_token():
    f = finding(scan('<form method="post" action="/contact"><input name="email"></form>'), "source.csrf.hint")
    assert f.severity == Severity.LOW


def test_csrf_token_input_suppresses_hint():
    r = scan('<form method="post" action="/c"><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>')
    assert "source.csrf.hint" not in ids(r)


def test_csrf_meta_suppresses_hint():
    r = scan('<meta name="csrf-token" content="abc"><form method="post" action="/c"></form>')
    assert "source.csrf.hint" not in ids(r)


def test_csrf_samesite_strict_session_is_info():
    r = scan('<form method="post" action="/c"></form>',
             set_cookies=["PHPSESSID=abc; Secure; HttpOnly; SameSite=Strict"])
    assert finding(r, "source.csrf.hint").severity == Severity.INFO


def test_get_forms_do_not_trigger_csrf_hint():
    r = scan('<form method="get" action="/search"><input name="q"></form>')
    assert "source.csrf.hint" not in ids(r)
