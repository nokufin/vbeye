import pytest
from conftest import make_ctx, make_response

from vbeye.checkers import headers
from vbeye.scoring import Severity

SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def scan(url="https://example.com/", *, headers_=None, set_cookies=None, status=200,
         final_url=None, history=None, base=True):
    hdrs = dict(SECURE_HEADERS) if base else {}
    hdrs.update(headers_ or {})
    resp = make_response(final_url or url, status=status, headers=hdrs,
                         set_cookies=set_cookies, history_urls=history)
    ctx = make_ctx(url, response=resp)
    ctx.page.requested_url = url
    return headers.run(ctx)


def ids(result):
    return {f.check_id for f in result.findings}


def by_id(result, check_id):
    return [f for f in result.findings if f.check_id == check_id]


def test_clean_site_is_ok():
    r = scan()
    assert r.error is None
    assert ids(r) == {"headers.ok"}
    assert r.meta["status_code"] == 200
    assert r.meta["final_url"] == "https://example.com/"


def test_page_error_is_passed_through():
    ctx = make_ctx(error="HTTP request failed: timeout")
    ctx.page.blocked_by = "challenges.cloudflare.com"
    r = headers.run(ctx)
    assert r.error == "HTTP request failed: timeout"
    assert r.meta["blocked_by"] == "challenges.cloudflare.com"
    assert r.findings == []


def test_missing_response_without_error():
    r = headers.run(make_ctx())
    assert r.error


@pytest.mark.parametrize("status", [404, 500, 503, 301])
def test_non_2xx(status):
    r = scan(status=status)
    f = by_id(r, "headers.response.non_2xx")
    assert len(f) == 1
    assert f[0].severity == Severity.INFO
    assert "headers.ok" not in ids(r)


def test_2xx_has_no_status_finding():
    assert "headers.response.non_2xx" not in ids(scan(status=204))


def test_no_https_redirect():
    r = scan("http://example.com/", final_url="http://example.com/")
    assert by_id(r, "headers.no_https_redirect")[0].severity == Severity.HIGH


def test_https_redirect_is_fine():
    r = scan("http://example.com/", final_url="https://example.com/", history=["http://example.com/"])
    assert "headers.no_https_redirect" not in ids(r)


def test_cross_host_redirect():
    r = scan("https://example.com/", final_url="https://www.example.com/", history=["https://example.com/"])
    f = by_id(r, "headers.redirect.cross_host")[0]
    assert f.severity == Severity.MEDIUM
    assert "example.com -> www.example.com" in f.title
    assert "301 https://example.com/" in f.evidence


def test_hsts_missing_on_https():
    r = scan(headers_={"Strict-Transport-Security": ""})
    assert by_id(r, "headers.hsts.missing")[0].severity == Severity.HIGH


def test_hsts_not_reported_on_http():
    r = scan("http://example.com/", final_url="http://example.com/",
             headers_={"Strict-Transport-Security": ""})
    assert "headers.hsts.missing" not in ids(r)


def test_hsts_weak():
    r = scan(headers_={"Strict-Transport-Security": "max-age=3600; includeSubDomains"})
    assert by_id(r, "headers.hsts.weak")[0].severity == Severity.MEDIUM


def test_hsts_no_subdomains():
    r = scan(headers_={"Strict-Transport-Security": "max-age=31536000"})
    assert by_id(r, "headers.hsts.no_subdomains")[0].severity == Severity.LOW


def test_csp_missing():
    r = scan(headers_={"Content-Security-Policy": "", "X-Frame-Options": "DENY"})
    assert by_id(r, "headers.csp.missing")[0].severity == Severity.HIGH
    assert "headers.xfo.missing" not in ids(r)


def test_csp_weak():
    r = scan(headers_={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'"})
    f = by_id(r, "headers.csp.weak")[0]
    assert f.severity == Severity.MEDIUM
    assert "'unsafe-inline'" in f.description


@pytest.mark.parametrize("fa", ["*", "https:", "'self' *"])
def test_frame_ancestors_permissive(fa):
    r = scan(headers_={"Content-Security-Policy": f"default-src 'self'; frame-ancestors {fa}"})
    assert by_id(r, "headers.xfo.frame_ancestors_permissive")[0].severity == Severity.MEDIUM


@pytest.mark.parametrize("fa", ["'none'", "'self'", "https://partner.example"])
def test_frame_ancestors_protective(fa):
    r = scan(headers_={"Content-Security-Policy": f"default-src 'self'; frame-ancestors {fa}"})
    assert not {i for i in ids(r) if i.startswith("headers.xfo")}


def test_xfo_missing_without_frame_ancestors():
    r = scan(headers_={"Content-Security-Policy": "default-src 'self'"})
    assert by_id(r, "headers.xfo.missing")[0].severity == Severity.HIGH


def test_xfo_invalid():
    r = scan(headers_={"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "ALLOW-FROM https://a"})
    assert by_id(r, "headers.xfo.invalid")[0].severity == Severity.LOW


def test_xfo_valid():
    r = scan(headers_={"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "sameorigin"})
    assert not {i for i in ids(r) if i.startswith("headers.xfo")}


def test_xcto():
    assert by_id(scan(headers_={"X-Content-Type-Options": ""}), "headers.xcto.missing")
    assert by_id(scan(headers_={"X-Content-Type-Options": "sniff"}), "headers.xcto.missing")


def test_referrer():
    assert by_id(scan(headers_={"Referrer-Policy": ""}), "headers.referrer.missing")
    assert by_id(scan(headers_={"Referrer-Policy": "unsafe-url"}), "headers.referrer.weak")


def test_permissions_policy():
    r = scan(headers_={"Permissions-Policy": ""})
    assert by_id(r, "headers.permissions.missing")[0].severity == Severity.INFO
    legacy = scan(headers_={"Permissions-Policy": "", "Feature-Policy": "camera 'none'"})
    assert "headers.permissions.missing" not in ids(legacy)


@pytest.mark.parametrize("value,severity", [
    ("PHP/5.6.40", Severity.CRITICAL),
    ("PHP/7.4.33", Severity.CRITICAL),
    ("PHP/8.0.30", Severity.CRITICAL),
    ("PHP/8.1.2", Severity.HIGH),
    ("PHP/8.2", Severity.HIGH),
])
def test_php_eol(value, severity):
    r = scan(headers_={"X-Powered-By": value})
    f = by_id(r, "headers.tech.php_eol")
    assert f[0].severity == severity
    assert "headers.disclosure.x-powered-by" not in ids(r)


def test_php_supported_version_is_disclosure_only():
    r = scan(headers_={"X-Powered-By": "PHP/8.4.1"})
    assert "headers.tech.php_eol" not in ids(r)
    assert "headers.disclosure.x-powered-by" not in ids(r)


def test_disclosure_with_version():
    r = scan(headers_={"Server": "nginx/1.18.0"})
    assert by_id(r, "headers.disclosure.server")[0].severity == Severity.LOW


def test_disclosure_without_version():
    r = scan(headers_={"Server": "cloudflare"})
    assert by_id(r, "headers.disclosure.server")[0].severity == Severity.INFO


def cookie_findings(cookies, url="https://example.com/"):
    r = scan(url, final_url=url, set_cookies=cookies)
    return [f for f in r.findings if f.check_id.startswith("headers.cookie.")]


@pytest.mark.parametrize("cookie,check_id,severity", [
    ("PHPSESSID=a; Path=/", "headers.cookie.session_flags", Severity.CRITICAL),
    ("PHPSESSID=a; Path=/; SameSite=Lax", "headers.cookie.session_flags", Severity.CRITICAL),
    ("PHPSESSID=a; HttpOnly; SameSite=Lax", "headers.cookie.session_flags", Severity.HIGH),
    ("PHPSESSID=a; Secure; SameSite=Lax", "headers.cookie.session_flags", Severity.HIGH),
    ("PHPSESSID=a; Secure; HttpOnly", "headers.cookie.flags", Severity.LOW),
    ("PHPSESSID=a; HttpOnly; SameSite=None", "headers.cookie.session_flags", Severity.HIGH),
    ("theme=dark", "headers.cookie.flags", Severity.LOW),
    ("theme=dark; HttpOnly; SameSite=None", "headers.cookie.flags", Severity.MEDIUM),
    ("XSRF-TOKEN=x; Path=/", "headers.cookie.csrf_flags", Severity.LOW),
])
def test_cookie_severity_matrix(cookie, check_id, severity):
    found = cookie_findings([cookie])
    assert len(found) == 1
    assert found[0].check_id == check_id
    assert found[0].severity == severity


def test_fully_flagged_cookies_produce_no_findings():
    assert cookie_findings([
        "PHPSESSID=a; Secure; HttpOnly; SameSite=Lax",
        "XSRF-TOKEN=x; Secure; SameSite=Strict",
        "theme=dark; Secure; HttpOnly; SameSite=Lax",
    ]) == []


def test_flag_words_in_name_or_value_do_not_count():
    found = cookie_findings(["sessionid=secure_httponly; Path=/"])
    assert found[0].severity == Severity.CRITICAL
    found = cookie_findings(["secure_session=x; HttpOnly; SameSite=Lax"])
    assert found[0].check_id == "headers.cookie.session_flags"
    assert found[0].severity == Severity.HIGH


def test_secure_not_required_over_http_for_session_cookie():
    found = cookie_findings(["PHPSESSID=a; HttpOnly"], url="http://example.com/")
    assert found[0].check_id == "headers.cookie.flags"
    assert found[0].severity == Severity.LOW


def test_csrf_cookie_needs_no_httponly():
    assert cookie_findings(["csrftoken=x; Secure; SameSite=Lax"]) == []


def test_non_session_cookie_name_not_escalated():
    found = cookie_findings(["author_pref=1"])
    assert found[0].check_id == "headers.cookie.flags"
    assert found[0].severity == Severity.LOW


def test_multiple_cookies_reported_separately():
    found = cookie_findings(["PHPSESSID=a", "theme=dark"])
    assert {f.check_id for f in found} == {"headers.cookie.session_flags", "headers.cookie.flags"}
