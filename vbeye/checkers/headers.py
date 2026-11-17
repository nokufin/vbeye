from __future__ import annotations

import re
from urllib.parse import urlparse

from vbeye.context import ScanContext
from vbeye.cookies import (
    is_csrf_token_cookie,
    is_likely_session_cookie,
    iter_set_cookie_headers,
    parse_set_cookie,
)
from vbeye.scoring import CheckerResult, Confidence, Finding, Severity

VERSION_RE = re.compile(r"\d+\.\d+")
PHP_VERSION_RE = re.compile(r"(?i)PHP/(\d+)\.(\d+)(?:\.(\d+))?")

# Branches without security support per https://www.php.net/supported-versions.php
PHP_EOL_CRITICAL = (
    (5, 0), (5, 1), (5, 2), (5, 3), (5, 4), (5, 5), (5, 6),
    (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),
    (8, 0),
)
PHP_EOL_HIGH = (
    (8, 1),
    (8, 2),
)

HSTS_MIN_MAX_AGE = 15552000

FRAME_ANCESTORS_RE = re.compile(r"(?i)frame-ancestors\s+([^;]+)")
PERMISSIVE_FA_SOURCES = {"*", "http:", "https:", "ws:", "wss:", "data:", "blob:", "filesystem:"}

DISCLOSURE_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
}


def _frame_ancestors_protects(value: str) -> bool:
    tokens = value.lower().split()
    if not tokens:
        return False
    if tokens == ["'none'"]:
        return True
    return not any(t in PERMISSIVE_FA_SOURCES for t in tokens)


def _norm(headers) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def _check_status(status: int | None) -> Finding | None:
    if status is None or 200 <= status < 300:
        return None
    return Finding(
        "headers.response.non_2xx",
        f"Non-success HTTP status ({status})",
        Severity.INFO,
        f"The final response returned HTTP {status}. Headers and page content may belong to an "
        f"error or maintenance page rather than the production site.",
        "Verify the target URL and re-run the scan against a page that returns 2xx.",
        evidence=f"HTTP {status}",
        confidence=Confidence.VERIFIED,
    )


def _check_hsts(h: dict, is_https: bool) -> Finding | None:
    v = h.get("strict-transport-security")
    if not v:
        # Browsers ignore HSTS over plain HTTP; headers.no_https_redirect covers that case.
        if not is_https:
            return None
        return Finding(
            "headers.hsts.missing",
            "Strict-Transport-Security missing",
            Severity.HIGH,
            "No Strict-Transport-Security header. Browsers will not enforce HTTPS on subsequent "
            "visits, leaving users exposed to SSL-stripping attacks.",
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            confidence=Confidence.VERIFIED,
        )
    parts = [p.strip().lower() for p in v.split(";")]
    max_age = 0
    for p in parts:
        if p.startswith("max-age="):
            try:
                max_age = int(p.split("=", 1)[1].strip('"'))
            except ValueError:
                pass
    if max_age < HSTS_MIN_MAX_AGE:
        return Finding(
            "headers.hsts.weak",
            "HSTS max-age too short",
            Severity.MEDIUM,
            f"HSTS max-age is {max_age} seconds, below the recommended minimum of 180 days.",
            "Set max-age to at least 15552000 (180 days); HSTS preload requires 31536000 (1 year).",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    if "includesubdomains" not in parts:
        return Finding(
            "headers.hsts.no_subdomains",
            "HSTS without includeSubDomains",
            Severity.LOW,
            "Subdomains are not covered by HSTS and can be reached over plain HTTP, which "
            "enables cookie injection from an attacker-controlled subdomain connection.",
            "Add the `includeSubDomains` directive once all subdomains serve HTTPS.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_csp(h: dict) -> Finding | None:
    v = h.get("content-security-policy")
    if not v:
        return Finding(
            "headers.csp.missing",
            "Content-Security-Policy missing",
            Severity.HIGH,
            "No Content-Security-Policy header. If an XSS flaw exists there is no browser-level "
            "mitigation; any injected inline or third-party script runs unrestricted.",
            "Deploy a CSP starting from `default-src 'self'` and tighten it iteratively "
            "(use Content-Security-Policy-Report-Only to roll out safely).",
            confidence=Confidence.VERIFIED,
        )
    lower = v.lower()
    risky = []
    if "'unsafe-inline'" in lower:
        risky.append("'unsafe-inline'")
    if "'unsafe-eval'" in lower:
        risky.append("'unsafe-eval'")
    if " * " in f" {lower} " or lower.strip().endswith(" *") or "src *" in lower:
        risky.append("wildcard source")
    if risky:
        return Finding(
            "headers.csp.weak",
            "Content-Security-Policy contains unsafe directives",
            Severity.MEDIUM,
            f"The policy allows {', '.join(risky)}, which largely negates its protection against XSS.",
            "Replace inline allowances with nonces or hashes and remove wildcard sources.",
            evidence=v[:300],
            confidence=Confidence.STRONG_INDICATOR,
        )
    return None


def _check_xfo(h: dict) -> Finding | None:
    csp = h.get("content-security-policy", "")
    fa_match = FRAME_ANCESTORS_RE.search(csp)
    if fa_match:
        fa_value = fa_match.group(1).strip()
        if _frame_ancestors_protects(fa_value):
            return None
        return Finding(
            "headers.xfo.frame_ancestors_permissive",
            "CSP frame-ancestors too permissive",
            Severity.MEDIUM,
            f"`frame-ancestors {fa_value}` allows framing from arbitrary origins and provides no "
            f"clickjacking protection.",
            "Restrict frame-ancestors to `'none'`, `'self'` or an explicit list of trusted origins.",
            evidence=f"frame-ancestors {fa_value}",
            confidence=Confidence.VERIFIED,
        )
    v = h.get("x-frame-options")
    if not v:
        return Finding(
            "headers.xfo.missing",
            "Clickjacking protection missing",
            Severity.HIGH,
            "Neither X-Frame-Options nor CSP frame-ancestors is set. The page can be embedded in a "
            "hostile iframe for UI-redressing (clickjacking) attacks.",
            "Add `X-Frame-Options: DENY` or the CSP directive `frame-ancestors 'none'`.",
            confidence=Confidence.VERIFIED,
        )
    if v.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return Finding(
            "headers.xfo.invalid",
            "Invalid X-Frame-Options value",
            Severity.LOW,
            f"X-Frame-Options is `{v}`. ALLOW-FROM is obsolete and ignored by modern browsers; "
            f"only DENY and SAMEORIGIN are honoured.",
            "Use `DENY` or `SAMEORIGIN`, or CSP frame-ancestors for an allowlist.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_xcto(h: dict) -> Finding | None:
    v = h.get("x-content-type-options")
    if not v or v.strip().lower() != "nosniff":
        return Finding(
            "headers.xcto.missing",
            "X-Content-Type-Options nosniff missing",
            Severity.LOW,
            "Browsers may MIME-sniff responses, allowing content uploaded as one type to be "
            "executed as script or stylesheet.",
            "Add `X-Content-Type-Options: nosniff`.",
            evidence=v or "",
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_referrer(h: dict) -> Finding | None:
    v = h.get("referrer-policy")
    if not v:
        return Finding(
            "headers.referrer.missing",
            "Referrer-Policy missing",
            Severity.LOW,
            "Without an explicit policy, full URLs including paths and query parameters may be "
            "sent to third-party sites in the Referer header.",
            "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
            confidence=Confidence.VERIFIED,
        )
    if v.strip().lower() in {"unsafe-url", "no-referrer-when-downgrade"}:
        return Finding(
            "headers.referrer.weak",
            "Referrer-Policy too permissive",
            Severity.LOW,
            f"`{v}` sends full URLs to other origins and may leak sensitive path or query data.",
            "Use `strict-origin-when-cross-origin` or `no-referrer`.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_permissions(h: dict) -> Finding | None:
    if h.get("permissions-policy") or h.get("feature-policy"):
        return None
    return Finding(
        "headers.permissions.missing",
        "Permissions-Policy missing",
        Severity.INFO,
        "No explicit restriction on powerful browser features (camera, microphone, geolocation, etc.).",
        "Define a minimal policy, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
        confidence=Confidence.VERIFIED,
    )


def _check_php_version(h: dict) -> Finding | None:
    v = h.get("x-powered-by", "")
    m = PHP_VERSION_RE.search(v)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    version = f"{major}.{minor}" + (f".{m.group(3)}" if m.group(3) else "")
    branch = (major, minor)

    if branch in PHP_EOL_CRITICAL:
        return Finding(
            "headers.tech.php_eol",
            f"End-of-life PHP {version}",
            Severity.CRITICAL,
            f"X-Powered-By reports PHP {version}. This branch has been out of security support for "
            f"years; publicly known vulnerabilities in the runtime will never be patched.",
            "Upgrade to a supported PHP branch (see php.net/supported-versions) after testing in "
            "staging, and remove the X-Powered-By header.",
            evidence=f"X-Powered-By: {v}",
            confidence=Confidence.VERIFIED,
        )
    if branch in PHP_EOL_HIGH:
        return Finding(
            "headers.tech.php_eol",
            f"End-of-life PHP {version}",
            Severity.HIGH,
            f"X-Powered-By reports PHP {version}. This branch recently reached end of security "
            f"support and no longer receives fixes for new vulnerabilities.",
            "Plan a short-term upgrade to a supported PHP branch and remove the X-Powered-By header.",
            evidence=f"X-Powered-By: {v}",
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_disclosure(h: dict) -> list[Finding]:
    out = []
    for key, label in DISCLOSURE_HEADERS.items():
        v = h.get(key)
        if not v:
            continue
        if key == "x-powered-by" and PHP_VERSION_RE.search(v):
            continue
        if VERSION_RE.search(v):
            out.append(
                Finding(
                    f"headers.disclosure.{key}",
                    f"Version disclosure via {label}",
                    Severity.LOW,
                    f"The {label} header discloses an exact software version, which helps attackers "
                    f"match the target against known exploits.",
                    "Remove the header or strip the version at the web server or reverse proxy.",
                    evidence=f"{label}: {v}",
                    confidence=Confidence.VERIFIED,
                )
            )
        else:
            out.append(
                Finding(
                    f"headers.disclosure.{key}",
                    f"Software identification via {label}",
                    Severity.INFO,
                    f"The {label} header names the server software without a version. Not directly "
                    f"exploitable, but it assists reconnaissance.",
                    "Remove the header or set a neutral value if there is no operational need for it.",
                    evidence=f"{label}: {v}",
                    confidence=Confidence.VERIFIED,
                )
            )
    return out


def _cookie_finding(name: str, raw: str, check_id: str, severity: Severity, title: str,
                    problems: list[str], impact: str, recommendation: str) -> Finding:
    return Finding(
        check_id,
        title,
        severity,
        f"Cookie `{name}` is missing: {', '.join(problems)}. {impact}",
        recommendation,
        evidence=raw[:200],
        confidence=Confidence.VERIFIED,
    )


def _check_cookies(set_cookies: list[str], is_https: bool) -> list[Finding]:
    out: list[Finding] = []
    for raw in set_cookies:
        name, _value, attrs = parse_set_cookie(raw)
        if not name:
            continue
        has_secure = "secure" in attrs
        has_httponly = "httponly" in attrs
        samesite = (attrs.get("samesite") or "").lower() if "samesite" in attrs else None
        samesite_none_insecure = samesite == "none" and not has_secure

        if is_csrf_token_cookie(name):
            problems = []
            if (is_https and not has_secure) or samesite_none_insecure:
                problems.append("Secure")
            if samesite is None:
                problems.append("SameSite")
            if problems:
                out.append(_cookie_finding(
                    name, raw, "headers.cookie.csrf_flags", Severity.LOW,
                    f"CSRF token cookie '{name}' missing attributes", problems,
                    "HttpOnly is intentionally absent for double-submit CSRF tokens, but Secure and "
                    "SameSite are still expected.",
                    "Set Secure and SameSite. HttpOnly is not required for double-submit CSRF tokens.",
                ))
            continue

        missing_secure = samesite_none_insecure or (is_https and not has_secure)
        missing_httponly = not has_httponly
        missing_samesite = samesite is None

        if is_likely_session_cookie(name):
            core = []
            if missing_secure:
                core.append("Secure (required with SameSite=None)" if samesite_none_insecure else "Secure")
            if missing_httponly:
                core.append("HttpOnly")
            if core:
                problems = core + (["SameSite"] if missing_samesite else [])
                if len(core) == 2:
                    severity = Severity.CRITICAL
                    impact = ("The session token can be sent over plain HTTP and read by injected "
                              "JavaScript, enabling session hijacking via network interception or XSS.")
                elif missing_secure:
                    severity = Severity.HIGH
                    impact = "The session token can be sent over plain HTTP and intercepted."
                else:
                    severity = Severity.HIGH
                    impact = "The session token is readable by JavaScript and can be stolen through XSS."
                out.append(_cookie_finding(
                    name, raw, "headers.cookie.session_flags", severity,
                    f"Session cookie '{name}' missing security attributes", problems, impact,
                    "Set Secure and HttpOnly on all session cookies, and SameSite=Lax or Strict.",
                ))
                continue
            if missing_samesite:
                out.append(_cookie_finding(
                    name, raw, "headers.cookie.flags", Severity.LOW,
                    f"Session cookie '{name}' without explicit SameSite", ["SameSite"],
                    "Modern browsers default to Lax, but older browsers send the cookie on "
                    "cross-site requests.",
                    "Set SameSite=Lax or Strict explicitly.",
                ))
            continue

        problems = []
        if missing_secure:
            problems.append("Secure (required with SameSite=None)" if samesite_none_insecure else "Secure")
        if missing_httponly:
            problems.append("HttpOnly")
        if missing_samesite:
            problems.append("SameSite")
        if not problems:
            continue
        if samesite_none_insecure:
            severity = Severity.MEDIUM
            impact = "Browsers reject SameSite=None cookies without Secure, which can break functionality."
        else:
            severity = Severity.LOW
            impact = "Hardening recommended to limit cross-site and script access."
        out.append(_cookie_finding(
            name, raw, "headers.cookie.flags", severity,
            f"Cookie '{name}' missing attributes", problems, impact,
            "Set Secure, HttpOnly (unless JavaScript needs access) and SameSite=Lax or Strict.",
        ))
    return out


def _check_redirects(ctx: ScanContext) -> list[Finding]:
    page = ctx.page
    resp = page.response
    out: list[Finding] = []

    if ctx.url.startswith("http://") and page.final_url.startswith("http://"):
        out.append(
            Finding(
                "headers.no_https_redirect",
                "No redirect from HTTP to HTTPS",
                Severity.HIGH,
                "The HTTP endpoint does not redirect to HTTPS, so traffic is unencrypted by default.",
                "Configure a permanent (301) redirect to HTTPS and enable HSTS.",
                evidence=f"{ctx.url} -> {page.final_url}",
                confidence=Confidence.VERIFIED,
            )
        )

    orig_host = (urlparse(page.requested_url).hostname or "").lower()
    final_host = page.final_host
    if orig_host and final_host and orig_host != final_host:
        chain = " -> ".join(f"{h.status_code} {h.url}" for h in resp.history)
        chain = f"{chain} -> {resp.status_code} {resp.url}" if chain else f"{resp.status_code} {resp.url}"
        out.append(
            Finding(
                "headers.redirect.cross_host",
                f"Cross-host redirect ({orig_host} -> {final_host})",
                Severity.MEDIUM,
                f"`{orig_host}` redirects to `{final_host}`. HSTS set on the final host never applies "
                f"to `{orig_host}`, so a first visit over HTTP to the original host can be intercepted.",
                "Redirect HTTP to HTTPS on the same host first, then change host, and send HSTS on both hosts.",
                evidence=chain,
                confidence=Confidence.VERIFIED,
            )
        )
    return out


def run(ctx: ScanContext) -> CheckerResult:
    result = CheckerResult(name="headers")
    page = ctx.page
    if page.error or page.response is None:
        result.error = page.error or "No HTTP response available."
        if page.blocked_by:
            result.meta["blocked_by"] = page.blocked_by
        return result

    resp = page.response
    result.meta["final_url"] = page.final_url
    result.meta["status_code"] = resp.status_code
    result.meta["headers"] = dict(resp.headers)

    status = _check_status(resp.status_code)
    if status:
        result.findings.append(status)

    result.findings.extend(_check_redirects(ctx))

    h = _norm(resp.headers)
    for f in (
        _check_hsts(h, page.is_https),
        _check_csp(h),
        _check_xfo(h),
        _check_xcto(h),
        _check_referrer(h),
        _check_permissions(h),
        _check_php_version(h),
    ):
        if f:
            result.findings.append(f)

    result.findings.extend(_check_disclosure(h))
    result.findings.extend(_check_cookies(iter_set_cookie_headers(resp), page.is_https))

    if not result.findings:
        result.findings.append(
            Finding(
                "headers.ok",
                "Security headers configured",
                Severity.OK,
                "All checked security headers are present and no obvious misconfiguration was found.",
                confidence=Confidence.VERIFIED,
            )
        )
    return result
