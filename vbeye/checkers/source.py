from __future__ import annotations

import base64
import math
import re
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup

from vbeye.context import ScanContext
from vbeye.cookies import is_likely_session_cookie, iter_set_cookie_headers
from vbeye.scoring import CheckerResult, Confidence, Finding, Severity

HIGH_CONFIDENCE_SECRETS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("GitHub PAT", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9]{24,}\b")),
]

# Same AIza format is used for public, referrer-restricted browser keys (Maps, YouTube) and server keys.
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

JWT_PATTERN_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

JWT_CRITICAL_KEYS_RE = re.compile(
    r'"(password|passwd|private[_-]?key|api[_-]?key|client[_-]?secret|'
    r'aws[_-]?(?:access|secret)[_-]?key|service[_-]?account|admin[_-]?token)"',
    re.IGNORECASE,
)

JWT_CLIENT_SIDE_KEYS_RE = re.compile(
    r'"(guest[_-]?uuid|guest[_-]?id|anonymous|consent|csrf|nonce|'
    r'session[_-]?id|sessionid|state|cf[_-]?ray|cf[_-]?bm|bot[_-]?id|'
    r'visitor[_-]?id|tracking[_-]?id|experiment|ab[_-]?test)"',
    re.IGNORECASE,
)

GENERIC_SECRET_RE = re.compile(
    r"""(?ix)
    \b(api[_-]?key|api[_-]?secret|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)
    \s*[:=]\s*
    ['"]([A-Za-z0-9+/=_\-\.]{20,})['"]
    """
)

PLACEHOLDER_RE = re.compile(
    r"^(your[-_ ]?|example[-_ ]?|test[-_ ]?|demo[-_ ]?|sample[-_ ]?|placeholder|xxx+|\.\.\.|<.+>|\{.+\})",
    re.IGNORECASE,
)

COMMENT_NOISE_RE = re.compile(
    r"(?ix)"
    r"(google\s*tag\s*manager|gtm\.start|googletagmanager|"
    r"cloudflare|rocket[\s\-_]?loader|wp[\s\-_]?rocket|cf[\s\-_]?cache|"
    r"google[\s\-_]?analytics|gtag\(|hotjar|facebook\s*pixel|"
    r"cookieconsent|onetrust|usercentrics|"
    r"yoast\s*seo|all\s*in\s*one\s*seo|jetpack|"
    r"page\s*generated\s*in|"
    r"<!\[endif\]|\[if\s+(?:lt\s+)?IE)"
)

COMMENT_LEAK_PATTERNS = [
    re.compile(r"(?i)\bTODO\s*[:\-]"),
    re.compile(r"(?i)\bFIXME\s*[:\-]"),
    re.compile(r"(?i)\bHACK\s*[:\-]"),
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]"),
    re.compile(r"(?i)\b(credential|api[_-]?key|api[_-]?token|secret|bearer|access[_-]?token)\s*[:=]"),
    re.compile(r"(?i)\binternal\s+(only|use|api|debug|note)\b"),
    re.compile(r"(?i)\b(stacktrace|traceback|stack\s+trace)\b"),
    re.compile(r"(?i)\bdebug\s*[:=]\s*true\b"),
]

RESOURCE_LINK_RELS = frozenset({
    "stylesheet", "icon", "apple-touch-icon", "apple-touch-icon-precomposed",
    "mask-icon", "preload", "modulepreload", "prefetch", "manifest",
})

SRI_LINK_RELS = frozenset({"stylesheet", "preload", "modulepreload"})

# Stylesheets served per user agent cannot carry a stable integrity hash.
SRI_EXEMPT_STYLE_HOSTS = ("fonts.googleapis.com", "use.typekit.net", "p.typekit.net", "fonts.bunny.net")

MIXED_CONTENT_ATTRS = (
    ("script", "src"),
    ("img", "src"),
    ("iframe", "src"),
    ("video", "src"),
    ("video", "poster"),
    ("audio", "src"),
    ("source", "src"),
    ("embed", "src"),
    ("track", "src"),
    ("input", "src"),
    ("object", "data"),
    ("body", "background"),
)

LIBRARY_PATTERNS = {
    "jquery": re.compile(r"(?i)(?<![\w.-])jquery[@/-]v?(\d+\.\d+(?:\.\d+)?)(?![\w-])"),
    "bootstrap": re.compile(r"(?i)(?<![\w.-])(?:twitter-)?bootstrap[@/-]v?(\d+\.\d+(?:\.\d+)?)(?![\w-])"),
    "angularjs": re.compile(r"(?i)(?<![\w.-])(?:angular\.js|angularjs|angular)[@/-]v?(1\.\d+(?:\.\d+)?)(?![\w-])"),
}

LIBRARY_FILE_PATTERNS = {
    "jquery": re.compile(r"(?i)(?:^|/)jquery(?:\.min)?\.js(?:$|[?#])"),
    "bootstrap": re.compile(r"(?i)(?:^|/)bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)(?:$|[?#])"),
    "angularjs": re.compile(r"(?i)(?:^|/)angular(?:\.min)?\.js(?:$|[?#])"),
}

WP_VERSION_RE = re.compile(r"(?i)[?&]ver=(\d+\.\d+(?:\.\d+)?)")

STALE_ANALYTICS_PATTERNS = [
    ("Universal Analytics (end of life 2023-07-01)", re.compile(r"\bUA-\d{4,}-\d+\b")),
    ("Legacy google-analytics.com script", re.compile(r"google-analytics\.com/(?:analytics|ga)\.js")),
    (
        "Universal Analytics via gtag.js (end of life 2023-07-01)",
        re.compile(r"googletagmanager\.com/gtag/js\?id=UA-\d+"),
    ),
]

CSRF_TOKEN_INPUT_NAMES = (
    "csrf", "_token", "authenticity_token", "xsrf",
    "csrfmiddlewaretoken", "__requestverificationtoken",
    "csrf_token", "csrf-token",
)

CSRF_META_NAME_RE = re.compile(r"(?i)^(csrf-token|_csrf|csrf-param|x-csrf-token|csrf|xsrf-token)$")


def run(ctx: ScanContext) -> CheckerResult:
    result = CheckerResult(name="source")
    page = ctx.page
    if page.error or page.response is None:
        result.error = page.error or "No HTTP response available."
        if page.blocked_by:
            result.meta["blocked_by"] = page.blocked_by
        return result

    resp = page.response
    final_url = page.final_url
    is_https = page.is_https
    html = resp.text
    result.meta["bytes"] = len(html)

    soup = BeautifulSoup(html, "html.parser")

    _check_mixed_content(soup, is_https, result)
    _check_sri(soup, final_url, result)
    _check_form_security(soup, final_url, is_https, result)
    _check_inline_code(soup, result)
    _check_comments(html, result)
    _check_secrets(html, result)
    _check_vulnerable_libs(soup, result)
    _check_stale_analytics(html, result)
    _check_csrf_token_hint(soup, resp, result)

    if not result.findings:
        result.findings.append(
            Finding(
                "source.ok",
                "No source-level issues found",
                Severity.OK,
                "The served HTML did not contain any of the checked issues.",
                confidence=Confidence.VERIFIED,
            )
        )
    return result


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _decode_jwt_payload(jwt_str: str) -> str | None:
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        return base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8", errors="replace")
    except Exception:
        return None


# Client-side session/state JWTs are routine on modern frontends; only payloads with
# server-side secret claims justify a critical finding.
def _classify_jwt(jwt_str: str) -> tuple[str, str]:
    payload = _decode_jwt_payload(jwt_str)
    if payload is None:
        return "hint", "<undecodable>"
    if JWT_CRITICAL_KEYS_RE.search(payload):
        return "critical", payload
    if JWT_CLIENT_SIDE_KEYS_RE.search(payload):
        return "skip", payload
    return "hint", payload


def _looks_like_real_secret(value: str) -> bool:
    if len(value) < 20:
        return False
    if PLACEHOLDER_RE.match(value):
        return False
    if re.fullmatch(r"[A-Z0-9_]{1,40}", value):
        return False
    return _shannon_entropy(value) >= 4.0


def _registrable_domain(url: str) -> str:
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return (urlparse(url).hostname or "").lower()


def _is_external(base: str, href: str) -> bool:
    try:
        base_root = _registrable_domain(base)
        ref_root = _registrable_domain(urljoin(base, href))
    except Exception:
        return False
    return bool(base_root) and bool(ref_root) and ref_root != base_root


def _link_rels(el) -> set[str]:
    rel = el.get("rel") or []
    if isinstance(rel, str):
        rel = rel.split()
    return {r.lower() for r in rel}


def _is_resource_link(el) -> bool:
    return bool(_link_rels(el) & RESOURCE_LINK_RELS)


def _is_protocol_relative(v: str) -> bool:
    return v.startswith("//") and not v.startswith("///")


def _classify_url(value: str, label: str, mixed: list[str], protocol_relative: list[str]) -> None:
    v = value.strip()
    if v.lower().startswith("http://"):
        mixed.append(f"{label}={v}")
    elif _is_protocol_relative(v):
        protocol_relative.append(f"{label}={v}")


def _check_mixed_content(soup: BeautifulSoup, is_https: bool, result: CheckerResult) -> None:
    if not is_https:
        return
    mixed: list[str] = []
    protocol_relative: list[str] = []

    for tag, attr in MIXED_CONTENT_ATTRS:
        for el in soup.find_all(tag):
            v = el.get(attr)
            if v:
                _classify_url(v, f"{tag} {attr}", mixed, protocol_relative)

    for el in soup.find_all("link", href=True):
        if _is_resource_link(el):
            _classify_url(el["href"], "link href", mixed, protocol_relative)

    for el in soup.find_all(["img", "source"]):
        srcset = el.get("srcset")
        if not srcset:
            continue
        for candidate in srcset.split(","):
            tokens = candidate.strip().split()
            if tokens:
                _classify_url(tokens[0], f"{el.name} srcset", mixed, protocol_relative)

    if mixed:
        result.findings.append(
            Finding(
                "source.mixed_content",
                "Mixed content (HTTP resources on an HTTPS page)",
                Severity.HIGH,
                f"{len(mixed)} resource(s) are loaded over plain HTTP from an HTTPS page. Browsers block "
                f"or warn on these, and a network attacker can modify them in transit.",
                "Serve every subresource over HTTPS and reference it with an explicit https:// URL.",
                evidence="\n".join(mixed[:10]),
                confidence=Confidence.VERIFIED,
            )
        )

    if protocol_relative:
        result.findings.append(
            Finding(
                "source.mixed_content.protocol_relative",
                "Protocol-relative resource URLs",
                Severity.LOW,
                f"{len(protocol_relative)} resource(s) use protocol-relative URLs (//host/path). On this HTTPS "
                f"page they load over HTTPS, so this is not mixed content. Explicit https:// URLs are "
                f"preferred as defense in depth and avoid HTTP loads if the page is ever served without TLS.",
                "Replace the // prefix with explicit https:// URLs.",
                evidence="\n".join(protocol_relative[:10]),
                confidence=Confidence.STRONG_INDICATOR,
            )
        )


def _check_sri(soup: BeautifulSoup, base: str, result: CheckerResult) -> None:
    missing: list[str] = []
    for s in soup.find_all("script", src=True):
        if _is_external(base, s["src"]) and not s.get("integrity"):
            missing.append(f"script {s['src']}")

    for el in soup.find_all("link", href=True):
        if not (_link_rels(el) & SRI_LINK_RELS):
            continue
        href = el["href"]
        if not _is_external(base, href) or el.get("integrity"):
            continue
        host = (urlparse(urljoin(base, href)).hostname or "").lower()
        if "stylesheet" in _link_rels(el) and host in SRI_EXEMPT_STYLE_HOSTS:
            continue
        missing.append(f"link {href}")

    if missing:
        result.findings.append(
            Finding(
                "source.sri.missing",
                "Third-party resources without Subresource Integrity",
                Severity.MEDIUM,
                f"{len(missing)} third-party script/style resource(s) are loaded without an integrity hash. "
                f"A compromise of the hosting CDN would allow arbitrary code execution on this site.",
                "Add integrity and crossorigin attributes to third-party script and stylesheet tags, "
                "or self-host the resources.",
                evidence="\n".join(missing[:10]),
                confidence=Confidence.STRONG_INDICATOR,
            )
        )


def _check_form_security(soup: BeautifulSoup, base: str, is_https: bool, result: CheckerResult) -> None:
    http_actions: list[str] = []
    password_forms = 0
    autocomplete_off = 0

    for form in soup.find_all("form"):
        action = form.get("action") or base
        if urljoin(base, action).lower().startswith("http://"):
            http_actions.append(str(form)[:300])
        pw = form.find("input", attrs={"type": "password"})
        if pw is None:
            continue
        if not is_https:
            password_forms += 1
        if (pw.get("autocomplete") or "").lower() == "off":
            autocomplete_off += 1

    if http_actions:
        result.findings.append(
            Finding(
                "source.form.http_action",
                "Form submits over HTTP",
                Severity.HIGH,
                f"{len(http_actions)} form(s) submit data to an http:// endpoint. Every field is sent "
                f"unencrypted and can be read or modified on the network.",
                "Point form actions to HTTPS endpoints.",
                evidence="\n---\n".join(http_actions[:5]),
                confidence=Confidence.VERIFIED,
            )
        )

    if password_forms:
        result.findings.append(
            Finding(
                "source.form.password_on_http",
                "Password field on a page served over HTTP",
                Severity.CRITICAL,
                f"{password_forms} form(s) with a password field are served without TLS. Credentials are "
                f"exposed to anyone on the network path.",
                "Serve the page and the form action over HTTPS only.",
                confidence=Confidence.VERIFIED,
            )
        )

    if autocomplete_off:
        result.findings.append(
            Finding(
                "source.form.autocomplete_off",
                "autocomplete=off on password field",
                Severity.INFO,
                "Disabling autocomplete on password fields hinders password managers and tends to push "
                "users toward weaker, reused passwords.",
                "Remove autocomplete=off from password fields; use MFA for additional protection.",
                confidence=Confidence.VERIFIED,
            )
        )


def _check_inline_code(soup: BeautifulSoup, result: CheckerResult) -> None:
    handlers: list[str] = []
    for el in soup.find_all(True):
        for attr in el.attrs:
            if attr.lower().startswith("on"):
                handlers.append(f"<{el.name} {attr}=...>")
                break
        if len(handlers) >= 8:
            break

    inline_scripts = sum(
        1 for s in soup.find_all("script") if not s.get("src") and (s.string or "").strip()
    )

    if handlers:
        result.findings.append(
            Finding(
                "source.inline_handlers",
                "Inline event handlers",
                Severity.LOW,
                f"Inline on* event handler attributes are present ({len(handlers)} example(s)). They prevent "
                f"deploying a strict Content-Security-Policy without 'unsafe-inline' or 'unsafe-hashes'.",
                "Move handlers to addEventListener calls in external scripts so a nonce- or hash-based CSP "
                "can be enforced.",
                evidence="\n".join(handlers),
                confidence=Confidence.VERIFIED,
            )
        )

    if inline_scripts:
        result.findings.append(
            Finding(
                "source.inline_scripts",
                f"Inline <script> blocks ({inline_scripts})",
                Severity.INFO,
                "Inline scripts are not a vulnerability by themselves, but they require a nonce- or "
                "hash-based CSP to be covered by a strict policy.",
                "Move scripts to external files or use a nonce/hash-based CSP.",
                confidence=Confidence.VERIFIED,
            )
        )


def _check_comments(html: str, result: CheckerResult) -> None:
    leaks: list[str] = []
    for c in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
        s = c.strip()
        if not s or COMMENT_NOISE_RE.search(s):
            continue
        if any(p.search(s) for p in COMMENT_LEAK_PATTERNS):
            leaks.append(s[:200])
        if len(leaks) >= 10:
            break

    if leaks:
        result.findings.append(
            Finding(
                "source.comments.leak",
                "Suspicious HTML comments",
                Severity.LOW,
                f"{len(leaks)} HTML comment(s) match developer-note or sensitive patterns (TODO:, password:, "
                f"internal use, stack trace). They may disclose internal details.",
                "Strip comments from production HTML during the build.",
                evidence="\n---\n".join(leaks),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n] + "..."


def _check_secrets(html: str, result: CheckerResult) -> None:
    verified_hits: list[str] = []
    for label, pat in HIGH_CONFIDENCE_SECRETS:
        for m in pat.finditer(html):
            verified_hits.append(f"{label}: {_truncate(m.group(0), 60)}")
            if len(verified_hits) >= 15:
                break

    jwt_critical: list[str] = []
    jwt_hints: list[str] = []
    seen_jwts: set[str] = set()
    for m in JWT_PATTERN_RE.finditer(html):
        jwt = m.group(0)
        if jwt in seen_jwts:
            continue
        seen_jwts.add(jwt)
        kind, payload = _classify_jwt(jwt)
        if kind == "critical":
            jwt_critical.append(f"JWT with secret claims: {_truncate(jwt, 60)}\n  payload: {payload[:200]}")
        elif kind == "hint":
            jwt_hints.append(f"JWT: {_truncate(jwt, 60)}\n  payload: {payload[:200]}")
        if len(jwt_critical) + len(jwt_hints) >= 10:
            break

    exposed = verified_hits + jwt_critical
    if exposed:
        result.findings.append(
            Finding(
                "source.secret.exposed",
                "Secret exposed in page source",
                Severity.CRITICAL,
                "The served content contains credentials in a well-known format (AWS, Slack, GitHub, "
                "Stripe key, PEM private key, or a JWT carrying server-side secret claims).",
                "Revoke and rotate the credential immediately, remove it from the frontend, and keep it "
                "server-side.",
                evidence="\n".join(exposed),
                confidence=Confidence.VERIFIED,
            )
        )

    if jwt_hints:
        result.findings.append(
            Finding(
                "source.secret.jwt_hint",
                "JWT embedded in page source",
                Severity.HIGH,
                f"{len(jwt_hints)} JWT(s) found in the served content. The payload shows neither typical "
                f"client-side markers (guest id, csrf, consent, session id) nor obvious secret claims, so "
                f"it cannot be classified passively.",
                "Decode the payload and review its claims. Client-side session or state tokens are "
                "expected; server or admin tokens must be revoked and removed.",
                evidence="\n---\n".join(jwt_hints),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )

    google_keys: list[str] = []
    for m in GOOGLE_API_KEY_RE.finditer(html):
        key = m.group(0)
        if key not in google_keys:
            google_keys.append(key)
        if len(google_keys) >= 10:
            break
    if google_keys:
        result.findings.append(
            Finding(
                "source.secret.google_api_key_hint",
                "Google API key in page source",
                Severity.HIGH,
                f"{len(google_keys)} Google API key(s) (AIza...) found. Browser keys for Maps, YouTube or "
                f"Firebase are public by design and should be referrer-restricted; server keys for Cloud "
                f"APIs must never be exposed. The two cannot be distinguished passively.",
                "Check each key in the Google Cloud Console. Restrict browser keys by HTTP referrer and "
                "API; rotate any server key and move it to the backend.",
                evidence="\n".join(google_keys),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )

    generic_hits: list[str] = []
    for m in GENERIC_SECRET_RE.finditer(html):
        if not _looks_like_real_secret(m.group(2)):
            continue
        generic_hits.append(f"{m.group(1)}: {_truncate(m.group(0), 80)}")
        if len(generic_hits) >= 10:
            break
    if generic_hits:
        result.findings.append(
            Finding(
                "source.secret.generic_hint",
                "Possible hardcoded secret (key = value)",
                Severity.HIGH,
                f"{len(generic_hits)} high-entropy value(s) assigned to secret-like names (api_key, "
                f"client_secret, access_token...). They may be real secrets or public configuration.",
                "Review each value manually. Rotate and remove any real secret; ignore public identifiers.",
                evidence="\n".join(generic_hits),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )


def _parse_version(version: str) -> tuple[int, int, int] | None:
    try:
        parts = [int(p) for p in version.split(".")[:3]]
    except ValueError:
        return None
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def _library_advisory(lib: str, version: str) -> str | None:
    v = _parse_version(version)
    if v is None:
        return None
    if lib == "jquery":
        if v >= (3, 5, 0):
            return None
        cves = ["CVE-2020-11022", "CVE-2020-11023"]
        if v < (3, 4, 0):
            cves.append("CVE-2019-11358")
        if v < (3, 0, 0):
            cves.append("CVE-2015-9251")
        return f"XSS / prototype pollution ({', '.join(cves)}); upgrade to 3.5.0 or later"
    if lib == "bootstrap":
        if v < (3, 4, 1) or (4, 0, 0) <= v < (4, 1, 2):
            return ("XSS in data attributes (CVE-2018-14040, CVE-2018-14041, CVE-2018-14042, "
                    "CVE-2019-8331); upgrade to 3.4.1 or 4.3.1+")
        if (4, 1, 2) <= v < (4, 3, 1):
            return "XSS via tooltip/popover data-template (CVE-2019-8331); upgrade to 4.3.1+"
        return None
    if lib == "angularjs" and v[0] == 1:
        return "AngularJS reached end of life in December 2021 and receives no security fixes"
    return None


def _detect_library(src: str) -> tuple[str, str] | None:
    for lib, pat in LIBRARY_PATTERNS.items():
        m = pat.search(src)
        if m:
            return lib, m.group(1)
    ver = WP_VERSION_RE.search(src)
    if ver:
        path = src.split("?", 1)[0] + "?"
        for lib, pat in LIBRARY_FILE_PATTERNS.items():
            if pat.search(path):
                return lib, ver.group(1)
    return None


def _check_vulnerable_libs(soup: BeautifulSoup, result: CheckerResult) -> None:
    sources = [s["src"] for s in soup.find_all("script", src=True)]
    sources += [el["href"] for el in soup.find_all("link", href=True) if _link_rels(el) & SRI_LINK_RELS]

    hits: list[str] = []
    seen: set[tuple[str, str]] = set()
    for src in sources:
        detected = _detect_library(src)
        if detected is None:
            continue
        lib, version = detected
        advisory = _library_advisory(lib, version)
        if advisory is None or (lib, version) in seen:
            continue
        seen.add((lib, version))
        hits.append(f"{lib} {version}: {advisory}\n  {src}")

    if hits:
        result.findings.append(
            Finding(
                "source.lib.outdated",
                "Outdated JavaScript library with known vulnerabilities",
                Severity.MEDIUM,
                f"{len(hits)} library version(s) referenced in resource URLs have published advisories.",
                "Upgrade the affected libraries and add a dependency audit (e.g. retire.js, npm audit) to CI.",
                evidence="\n".join(hits),
                confidence=Confidence.STRONG_INDICATOR,
            )
        )


def _check_stale_analytics(html: str, result: CheckerResult) -> None:
    hits: list[str] = []
    for label, pat in STALE_ANALYTICS_PATTERNS:
        m = pat.search(html)
        if m:
            hits.append(f"{label}: {m.group(0)}")

    if hits:
        result.findings.append(
            Finding(
                "source.tech.stale_analytics",
                "Deprecated analytics integration",
                Severity.LOW,
                f"The page references {len(hits)} discontinued analytics integration(s). Not a vulnerability "
                f"by itself, but a strong sign that the frontend has not been maintained for years.",
                "Remove the legacy snippet or migrate to a supported analytics product, and review the "
                "frontend dependencies.",
                evidence="\n".join(hits),
                confidence=Confidence.VERIFIED,
            )
        )


def _check_csrf_token_hint(soup: BeautifulSoup, resp, result: CheckerResult) -> None:
    post_forms = [f for f in soup.find_all("form") if (f.get("method") or "GET").upper() == "POST"]
    if not post_forms:
        return

    for form in post_forms:
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(k in name for k in CSRF_TOKEN_INPUT_NAMES):
                return

    meta = soup.find("meta", attrs={"name": CSRF_META_NAME_RE})
    if meta and meta.get("content"):
        return

    strict_session = any(
        is_likely_session_cookie(c.split("=", 1)[0].strip()) and "samesite=strict" in c.lower()
        for c in iter_set_cookie_headers(resp)
    )

    if strict_session:
        result.findings.append(
            Finding(
                "source.csrf.hint",
                "POST form without explicit CSRF token (SameSite=Strict session)",
                Severity.INFO,
                "POST forms carry no CSRF token field or meta tag, but the session cookie is "
                "SameSite=Strict, which blocks cross-site submissions in modern browsers.",
                "Confirm that state-changing endpoints rely on SameSite and also validate Origin/Referer.",
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )
    else:
        result.findings.append(
            Finding(
                "source.csrf.hint",
                "No visible CSRF protection on POST form",
                Severity.LOW,
                "POST forms carry no CSRF token field or meta tag and no SameSite=Strict session cookie was "
                "observed. Protection may still exist server-side (Origin checks, header tokens).",
                "Verify server-side CSRF protection manually. If none exists, add synchronizer tokens or "
                "SameSite=Strict session cookies.",
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )
