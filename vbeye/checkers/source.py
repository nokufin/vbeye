from __future__ import annotations

import base64
import math
import re
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from vbeye import __version__
from vbeye.bot_protection import bot_protection_error_text, is_bot_protection_host
from vbeye.cookies import is_likely_session_cookie, iter_set_cookie_headers
from vbeye.scoring import CheckerResult, Confidence, Finding, Severity


USER_AGENT = f"vbeye/{__version__} (+https://github.com/nokufin/vbeye)"

REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "hu-HU,hu;q=0.9,en;q=0.8",
}

# Format-specific patterns — high precision, low false-positive rate.
# JWT is handled separately below: the payload is decoded and classified
# (client-side session token vs. real server-secret leak) before deciding
# severity. A bare JWT pattern alone is too ambiguous to call CRITICAL.
HIGH_CONFIDENCE_SECRETS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Slack token", re.compile(r"xox[abprs]-[0-9A-Za-z\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("GitHub PAT", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9]{24,}\b")),
]

# Google API key (AIza...) is handled separately: the same format covers both
# server-side keys (Cloud Storage, Vision, etc.) AND client-side keys (Maps JS,
# YouTube Embed, Analytics). Client-side keys are by-design publicly visible
# and domain-restricted in the Google Cloud Console. Cannot distinguish from
# passive HTML scan — emit HIGH + REQUIRES_MANUAL_VALIDATION instead of CRITICAL.
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

# JWT pattern (3-segment base64url with eyJ header prefix on first two segments)
JWT_PATTERN_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
)

# JWT payload keys that indicate a real server-secret leak.
JWT_CRITICAL_KEYS_RE = re.compile(
    r'"(password|passwd|private[_-]?key|api[_-]?key|client[_-]?secret|'
    r'aws[_-]?(?:access|secret)[_-]?key|service[_-]?account|admin[_-]?token)"',
    re.IGNORECASE,
)

# JWT payload keys that indicate a client-side session/state/anonymous token.
# These are routine on modern frontends and are NOT secret material.
JWT_CLIENT_SIDE_KEYS_RE = re.compile(
    r'"(guest[_-]?uuid|guest[_-]?id|anonymous|consent|csrf|nonce|'
    r'session[_-]?id|sessionid|state|cf[_-]?ray|cf[_-]?bm|bot[_-]?id|'
    r'visitor[_-]?id|tracking[_-]?id|experiment|ab[_-]?test)"',
    re.IGNORECASE,
)

# Heuristic generic-secret pattern — produces a separate, lower-confidence finding.
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

# HTML comments injected by common tooling — these are noise, not leaks.
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

# Only structured patterns trigger a finding — substrings like "password manager"
# or "rocket-loader debug=" must not match.
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


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def _decode_jwt_payload(jwt_str: str) -> str | None:
    """Decode the middle (payload) segment of a JWT.
    Returns the decoded JSON string, or None if the JWT cannot be parsed."""
    parts = jwt_str.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_b64 + padding)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def _classify_jwt(jwt_str: str) -> tuple[str, str]:
    """Classify a JWT pattern based on decoded payload content.

    Returns (classification, payload_preview):
      - 'critical'  → payload contains server-side secret keys (password, etc.)
      - 'skip'      → payload contains client-side session/anonymous markers
      - 'hint'      → ambiguous; needs manual validation
    """
    payload = _decode_jwt_payload(jwt_str)
    if payload is None:
        return ("hint", "<undecodable>")
    if JWT_CRITICAL_KEYS_RE.search(payload):
        return ("critical", payload)
    if JWT_CLIENT_SIDE_KEYS_RE.search(payload):
        return ("skip", payload)
    return ("hint", payload)


def _looks_like_real_secret(value: str) -> bool:
    if len(value) < 20:
        return False
    if PLACEHOLDER_RE.match(value):
        return False
    if re.fullmatch(r"[A-Z0-9_]{1,40}", value):
        return False
    return _shannon_entropy(value) >= 4.0

VULNERABLE_LIBS = {
    "jquery": [
        (re.compile(r"jquery[/\-]v?(1\.[0-9]+(\.[0-9]+)?)"), "1.x", "XSS via $.html() (CVE-2020-11022/23) — frissítés 3.5+"),
        (re.compile(r"jquery[/\-]v?(2\.[0-9]+(\.[0-9]+)?)"), "2.x", "XSS via $.html() — frissítés 3.5+"),
        (re.compile(r"jquery[/\-]v?(3\.([0-4])(\.[0-9]+)?)"), "3.0-3.4", "CVE-2020-11022/23 — frissítés 3.5+"),
    ],
    "bootstrap": [
        (re.compile(r"bootstrap[/\-]v?([23]\.[0-9]+\.[0-9]+)"), "2.x/3.x", "XSS issuek (CVE-2019-8331) — frissítés 4.3.1+"),
    ],
    "angular": [
        (re.compile(r"angular[/\-]v?(1\.[0-7]\.[0-9]+)"), "1.0-1.7", "Lifecycle vége, ismert XSS/sebezhetőségek — migrálj"),
    ],
}


# WordPress / classic asset URLs put the version in a `?ver=` query string,
# which the inline patterns above can't capture. Detect lib name in the path
# and check the version separately.
WP_VERSION_RE = re.compile(r"[?&]ver=(\d+\.\d+(?:\.\d+)?)", re.I)
LIB_NAME_IN_PATH_RE = {
    "jquery":    re.compile(r"(?i)(?:^|/)jquery(?:\.min)?\.js(?:$|[?&])"),
    "bootstrap": re.compile(r"(?i)(?:^|/)bootstrap(?:\.min)?\.(?:js|css)(?:$|[?&])"),
    "angular":   re.compile(r"(?i)(?:^|/)angular(?:\.min)?\.js(?:$|[?&])"),
}


def _vuln_range_note(lib: str, version: str) -> tuple[str, str] | None:
    """Return (version_label, note) if version is in a known-vulnerable range."""
    try:
        major, minor = (int(p) for p in version.split(".")[:2])
    except ValueError:
        return None
    if lib == "jquery":
        if major < 3:
            return f"{major}.x", "XSS via $.html() (CVE-2020-11022/23) — frissítés 3.5+"
        if major == 3 and minor < 5:
            return f"3.{minor}", "CVE-2020-11022/23 — frissítés 3.5+"
    elif lib == "bootstrap":
        if major in (2, 3):
            return f"{major}.x", "XSS issuek (CVE-2019-8331) — frissítés 4.3.1+"
    elif lib == "angular":
        if major == 1 and minor <= 7:
            return f"1.{minor}", "Lifecycle vége, ismert XSS/sebezhetőségek — migrálj"
    return None


def _absolute(base: str, href: str) -> str:
    return urljoin(base, href)


def _registrable_domain(url: str) -> str:
    """Return the registrable (eTLD+1) portion of a URL, e.g. 'example.com'."""
    try:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return (urlparse(url).hostname or "").lower()


def _is_external(base: str, href: str) -> bool:
    """True only when the resource is on a *different* registrable domain.
    Subdomains of the same org (static.example.com from www.example.com) are
    NOT external — they typically share trust boundary."""
    try:
        base_root = _registrable_domain(base)
        ref_root = _registrable_domain(_absolute(base, href))
        return ref_root != "" and base_root != "" and ref_root != base_root
    except Exception:
        return False


def run(url: str, timeout: int = 10) -> CheckerResult:
    result = CheckerResult(name="source")
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=REQUEST_HEADERS,
        )
    except requests.RequestException as e:
        result.error = f"HTTP lekérés sikertelen: {e}"
        return result

    final_url = resp.url
    is_https = final_url.startswith("https://")

    # Bot-management / WAF challenge: ha a redirect challenge-oldalra ment, ne
    # mérjük annak HTML-jét — abort egyértelmű hibával.
    _final_host = (urlparse(final_url).hostname or "").lower()
    if is_bot_protection_host(_final_host):
        result.error = bot_protection_error_text(_final_host)
        result.meta["blocked_by"] = _final_host
        return result

    html = resp.text
    result.meta["bytes"] = len(html)

    soup = BeautifulSoup(html, "html.parser")

    _check_mixed_content(soup, final_url, is_https, result)
    _check_external_scripts_sri(soup, final_url, result)
    _check_form_security(soup, final_url, is_https, result)
    _check_inline_handlers(soup, result)
    _check_comments(html, result)
    _check_secrets(html, result)
    _check_vulnerable_libs(soup, final_url, result)
    _check_stale_analytics(soup, html, result)
    _check_csrf_token_hint(soup, resp, result)

    if not result.findings:
        result.findings.append(
            Finding(
                "source.ok",
                "Forráskód-elemzés rendben",
                Severity.OK,
                "A nyilvánosan visszaadott HTML-ben nem találtam tipikus hibákat.",
                confidence=Confidence.VERIFIED,
            )
        )
    return result


MIXED_CONTENT_ATTRS = (
    ("script", "src"),
    ("link", "href"),
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


def _is_protocol_relative(v: str) -> bool:
    """`//host/path` — protocol-relative URL. Inherits page protocol → HTTP on HTTP visits."""
    return v.startswith("//") and not v.startswith("///")


def _check_mixed_content(soup: BeautifulSoup, base: str, is_https: bool, result: CheckerResult) -> None:
    if not is_https:
        return
    mixed = []
    protocol_relative = []
    for tag, attr in MIXED_CONTENT_ATTRS:
        for el in soup.find_all(tag):
            v = el.get(attr)
            if not v:
                continue
            if v.startswith("http://"):
                mixed.append(f"{tag} {attr}={v}")
            elif _is_protocol_relative(v):
                protocol_relative.append(f"{tag} {attr}={v}")
    # srcset attribute (img / source) carries comma-separated URL+descriptor pairs.
    for el in soup.find_all(["img", "source"]):
        srcset = el.get("srcset")
        if not srcset:
            continue
        for candidate in srcset.split(","):
            tokens = candidate.strip().split()
            if not tokens:
                continue
            url = tokens[0]
            if url.startswith("http://"):
                mixed.append(f"{el.name} srcset={url}")
            elif _is_protocol_relative(url):
                protocol_relative.append(f"{el.name} srcset={url}")

    if mixed:
        result.findings.append(
            Finding(
                "source.mixed_content",
                "Mixed content (HTTP erőforrás HTTPS oldalon)",
                Severity.HIGH,
                f"{len(mixed)} darab HTTP erőforrás a HTTPS oldalon. A böngészők blokkolják vagy figyelmeztetnek; MITM esetén injektálható.",
                "Cseréld a HTTP URL-eket explicit HTTPS-re.",
                evidence="\n".join(mixed[:10]),
                confidence=Confidence.VERIFIED,
            )
        )

    if protocol_relative:
        result.findings.append(
            Finding(
                "source.mixed_content.protocol_relative",
                "Protocol-relative URL-ek (HTTP-n mixed content lesz)",
                Severity.HIGH,
                f"{len(protocol_relative)} erőforrás protocol-relative URL-lel (`//host/...`) töltődik. "
                f"HTTPS oldalon HTTPS-ként megy, DE ha a látogató HTTP-n érkezik a bare domain-re "
                f"(első látogatás, lejárt HSTS, HSTS nélküli site), ezek HTTP-n töltődnek és MITM "
                f"esetén tetszőleges JavaScript injektálható. A modern legjobb gyakorlat: explicit `https://`.",
                "Cseréld a `//` prefixet explicit `https://`-re minden script/link/img/iframe URL-en.",
                evidence="\n".join(protocol_relative[:10]),
                confidence=Confidence.VERIFIED,
            )
        )


def _check_external_scripts_sri(soup: BeautifulSoup, base: str, result: CheckerResult) -> None:
    missing = []
    for s in soup.find_all("script", src=True):
        src = s["src"]
        if _is_external(base, src) and not s.get("integrity"):
            missing.append(src)
    if missing:
        result.findings.append(
            Finding(
                "source.sri.missing",
                "Külső script SRI nélkül",
                Severity.MEDIUM,
                f"{len(missing)} külső script SRI integrity hash nélkül töltődik be. Ha a CDN kompromittálódik, tetszőleges kódot injektálhat.",
                "Adj `integrity` attribútumot minden külső script/style tag-nek, és `crossorigin` megfelelő értékkel.",
                evidence="\n".join(missing[:10]),
                confidence=Confidence.STRONG_INDICATOR,
            )
        )


def _check_form_security(soup: BeautifulSoup, base: str, is_https: bool, result: CheckerResult) -> None:
    for form in soup.find_all("form"):
        action = form.get("action") or base
        absolute_action = _absolute(base, action)
        # form HTTP-n POST-ol
        if absolute_action.startswith("http://"):
            result.findings.append(
                Finding(
                    "source.form.http_action",
                    "Űrlap HTTP action-nel",
                    Severity.HIGH,
                    f"A form `{action}` HTTP-n keresztül küld adatot — minden mező látható a hálózaton.",
                    "Cseréld HTTPS action-re.",
                    evidence=str(form)[:300],
                    confidence=Confidence.VERIFIED,
                )
            )
        # password mező nem-HTTPS oldalon
        if not is_https and form.find("input", attrs={"type": "password"}):
            result.findings.append(
                Finding(
                    "source.form.password_on_http",
                    "Jelszó mező HTTP oldalon",
                    Severity.CRITICAL,
                    "Az oldal nem HTTPS, de password input van — a jelszó tisztán fog átmenni a hálózaton.",
                    "Töltsd be az űrlapot HTTPS-en, és a POST action is HTTPS legyen.",
                    confidence=Confidence.VERIFIED,
                )
            )
        # autocomplete=off password mezőn — info-szintű
        pw = form.find("input", attrs={"type": "password"})
        if pw and pw.get("autocomplete") == "off":
            result.findings.append(
                Finding(
                    "source.form.autocomplete_off",
                    "autocomplete=off password mezőn",
                    Severity.INFO,
                    "Az autocomplete=off password mezőn rontja a jelszókezelők használatát, gyengébb jelszavakhoz vezethet.",
                    "Hagyd a böngésző / password manager kezelni, és inkább MFA-t adj hozzá.",
                    confidence=Confidence.VERIFIED,
                )
            )


def _check_inline_handlers(soup: BeautifulSoup, result: CheckerResult) -> None:
    handlers = []
    for el in soup.find_all(True):
        for attr in list(el.attrs.keys()):
            if attr.lower().startswith("on"):
                handlers.append(f"<{el.name} {attr}=...>")
                if len(handlers) >= 8:
                    break
        if len(handlers) >= 8:
            break

    inline_scripts = sum(1 for s in soup.find_all("script") if not s.get("src") and (s.string or "").strip())
    if handlers:
        result.findings.append(
            Finding(
                "source.inline_handlers",
                "Inline event handlerek",
                Severity.LOW,
                f"Inline onXxx handlerek találhatók ({len(handlers)} példa). Ez nehezíti a szigorú CSP használatát.",
                "Mozgasd a handlereket addEventListenerbe, hogy lehessen szigorú CSP-t (nonce/hash) bevezetni.",
                evidence="\n".join(handlers),
                confidence=Confidence.VERIFIED,
            )
        )
    if inline_scripts > 0:
        result.findings.append(
            Finding(
                "source.inline_scripts",
                f"Inline <script> blokkok ({inline_scripts})",
                Severity.INFO,
                "Inline scriptek megnehezítik a szigorú CSP-t. Önmagukban nem hiba, de XSS-impactot növelnek.",
                "Külső fájlba mozgasd vagy nonce/hash alapú CSP-t használj.",
                confidence=Confidence.VERIFIED,
            )
        )


def _check_comments(html: str, result: CheckerResult) -> None:
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    leaks = []
    for c in comments:
        s = c.strip()
        if not s:
            continue
        if COMMENT_NOISE_RE.search(s):
            continue
        for pat in COMMENT_LEAK_PATTERNS:
            if pat.search(s):
                leaks.append(s[:200])
                break
        if len(leaks) >= 10:
            break
    if leaks:
        result.findings.append(
            Finding(
                "source.comments.leak",
                "Gyanús HTML-kommentek",
                Severity.LOW,
                f"{len(leaks)} komment strukturált, érzékeny mintát tartalmaz (TODO:, password:, internal use, stacktrace...). Belső fejlesztői infó szivároghatott.",
                "Távolítsd el a kommenteket build során (HTML minifier), és ne tarts production-ben fejlesztői megjegyzést.",
                evidence="\n---\n".join(leaks),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )


def _check_secrets(html: str, result: CheckerResult) -> None:
    verified_hits = []
    for label, pat in HIGH_CONFIDENCE_SECRETS:
        for m in pat.finditer(html):
            snippet = m.group(0)
            verified_hits.append(f"{label}: {snippet[:60]}{'…' if len(snippet) > 60 else ''}")
            if len(verified_hits) >= 15:
                break

    # JWT — decode payload and classify as critical / skip / hint
    jwt_critical_hits = []
    jwt_hint_hits = []
    seen_jwts: set[str] = set()
    for m in JWT_PATTERN_RE.finditer(html):
        jwt = m.group(0)
        if jwt in seen_jwts:
            continue
        seen_jwts.add(jwt)
        classification, payload = _classify_jwt(jwt)
        prefix = jwt[:60] + ("…" if len(jwt) > 60 else "")
        if classification == "critical":
            jwt_critical_hits.append(
                f"JWT (server-secret payload): {prefix}\n  payload: {payload[:200]}"
            )
        elif classification == "hint":
            jwt_hint_hits.append(
                f"JWT: {prefix}\n  payload: {payload[:200]}"
            )
        # 'skip' → no finding (client-side guest/session/state token)
        if len(jwt_critical_hits) + len(jwt_hint_hits) >= 10:
            break

    all_critical = verified_hits + jwt_critical_hits
    if all_critical:
        result.findings.append(
            Finding(
                "source.secret.exposed",
                "Konkrét formátumú titok a HTML-ben",
                Severity.CRITICAL,
                "A kiszolgált tartalom formátum-specifikus titok-mintát tartalmaz "
                "(AWS / Google / Slack / GitHub / Stripe kulcs, PEM private key block, "
                "vagy szerver-titkot tartalmazó JWT). Azonnal rotálandó, ha valódi.",
                "Rotáld a kulcsot, töröld a HTML-ből, mozgasd backendbe / env változóba.",
                evidence="\n".join(all_critical),
                confidence=Confidence.VERIFIED,
            )
        )

    if jwt_hint_hits:
        result.findings.append(
            Finding(
                "source.secret.jwt_hint",
                "JWT token a HTML-ben (kézi vizsgálat szükséges)",
                Severity.HIGH,
                f"{len(jwt_hint_hits)} JWT token található a kiszolgált tartalomban. "
                f"A payload nem tartalmaz egyértelmű kliens-oldali jelzőt (guest_uuid, "
                f"csrf, consent, session_id, anonymous stb.), de nyilvánvaló szerver-titok "
                f"mintát sem. Passzív scan-ből nem dönthető el, hogy rutin kliens-oldali "
                f"session-token (Next.js, Auth0, Cloudflare anonymous), VAGY szerver-titok "
                f"kiszivárgása.",
                "Decode-old a JWT payload-ot (jwt.io vagy `base64 -d`), és ellenőrizd: "
                "ha kliens-szintű session/state token → OK; ha szerver-token vagy admin "
                "claim → rotáld azonnal és töröld a HTML-ből.",
                evidence="\n---\n".join(jwt_hint_hits),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )

    # Google API key (AIza) — same ambiguity as JWT. The format covers both
    # server-side keys and publicly-visible client-side keys (Maps, YouTube,
    # Analytics). Cannot distinguish from passive scan → HIGH + manual.
    google_key_hits = []
    seen_google_keys: set[str] = set()
    for m in GOOGLE_API_KEY_RE.finditer(html):
        key = m.group(0)
        if key in seen_google_keys:
            continue
        seen_google_keys.add(key)
        google_key_hits.append(key)
        if len(google_key_hits) >= 10:
            break
    if google_key_hits:
        result.findings.append(
            Finding(
                "source.secret.google_api_key_hint",
                "Google API kulcs a HTML-ben (kézi vizsgálat szükséges)",
                Severity.HIGH,
                f"{len(google_key_hits)} Google API kulcs (AIza...) található a kiszolgált "
                f"tartalomban. Ugyanaz a formátum mind a szerver-oldali kulcsokhoz (Cloud "
                f"Storage, Vision, Translate, BigQuery), mind a kliens-oldali kulcsokhoz "
                f"(Maps JS, YouTube Embed, Analytics). A kliens-oldali kulcsok by-design "
                f"publikusak és a Google Cloud Console-ban domain-restriction-nel védettek. "
                f"Passzív scan-ből nem dönthető el, hogy melyik típus.",
                "Ellenőrizd a Google Cloud Console-ban: ha kliens-oldali, korlátozott "
                "Maps/YouTube/Analytics kulcs → OK marad. Ha szerver-oldali (Cloud Storage, "
                "Compute, BigQuery stb.) → azonnal rotálandó és backendbe / env változóba.",
                evidence="\n".join(google_key_hits),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )

    generic_hits = []
    for m in GENERIC_SECRET_RE.finditer(html):
        key_name = m.group(1)
        value = m.group(2)
        if not _looks_like_real_secret(value):
            continue
        snippet = m.group(0)
        generic_hits.append(f"{key_name}: {snippet[:80]}{'…' if len(snippet) > 80 else ''}")
        if len(generic_hits) >= 10:
            break
    if generic_hits:
        result.findings.append(
            Finding(
                "source.secret.generic_hint",
                "Generic key=érték minta a HTML-ben",
                Severity.HIGH,
                f"{len(generic_hits)} darab `{{kulcsnév}}: \"...\"` mintát találtam, ami valódi titok is lehet, de lehet konfiguráció / placeholder is. Entrópiaszűrés átengedte.",
                "Kézi validáció: nyisd meg az oldalt, és ellenőrizd hogy a megjelölt érték valós titok-e. Ha igen, rotáld; ha nem, ignore.",
                evidence="\n".join(generic_hits),
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )


def _check_vulnerable_libs(soup: BeautifulSoup, base: str, result: CheckerResult) -> None:
    sources = []
    for s in soup.find_all("script", src=True):
        sources.append(s["src"])
    for s in soup.find_all("link", href=True):
        sources.append(s["href"])

    hits = []
    seen = set()
    for src in sources:
        matched = False
        for lib, patterns in VULNERABLE_LIBS.items():
            for pat, version_label, note in patterns:
                if pat.search(src):
                    key = (lib, version_label, src)
                    if key not in seen:
                        seen.add(key)
                        hits.append(f"{lib} {version_label} — {src} ({note})")
                    matched = True
                    break
            if matched:
                break
        if matched:
            continue
        # Fallback: WordPress-style `?ver=X.Y.Z` query string where the inline
        # patterns don't catch the version because the URL is /jquery.min.js?ver=...
        wp_ver_match = WP_VERSION_RE.search(src)
        if not wp_ver_match:
            continue
        version = wp_ver_match.group(1)
        for lib, path_re in LIB_NAME_IN_PATH_RE.items():
            if path_re.search(src):
                vuln = _vuln_range_note(lib, version)
                if vuln:
                    version_label, note = vuln
                    key = (lib, version_label, src)
                    if key not in seen:
                        seen.add(key)
                        hits.append(f"{lib} {version_label} — {src} ({note})")
                break

    if hits:
        result.findings.append(
            Finding(
                "source.lib.outdated",
                "Régi/sebezhető library verzió",
                Severity.MEDIUM,
                f"{len(hits)} potenciálisan sebezhető library verziónak látszik az URL-ekben.",
                "Frissítsd a library-kat, retire.js-szel ellenőrizd a CI-ban.",
                evidence="\n".join(hits),
                confidence=Confidence.STRONG_INDICATOR,
            )
        )


STALE_ANALYTICS_PATTERNS = [
    # Universal Analytics — EoL 2023-07, no longer collects data
    ("Universal Analytics (Google) — EoL 2023-07-01",
     re.compile(r"\bUA-\d{4,}-\d+\b")),
    # google-analytics.com/analytics.js or ga.js — pre-GA4 classic
    ("Classic google-analytics.com script — deprecated, no data flow",
     re.compile(r"google-analytics\.com/(?:analytics|ga)\.js")),
    # Tag Manager URL with UA id (also Universal Analytics under GTM)
    ("Universal Analytics under GTM — EoL 2023-07-01",
     re.compile(r"googletagmanager\.com/gtag/js\?id=UA-\d+")),
]


def _check_stale_analytics(soup, html: str, result: CheckerResult) -> None:
    """Detect references to deprecated analytics/tracking platforms. These don't
    pose direct security risk but signal that the site has not been touched in
    1-3+ years — useful as a maintenance/abandonment indicator."""
    hits = []
    for label, pat in STALE_ANALYTICS_PATTERNS:
        for m in pat.finditer(html):
            snippet = m.group(0)
            if not any(snippet in h for h in hits):
                hits.append(f"{label}: {snippet}")
                break
    if hits:
        result.findings.append(
            Finding(
                "source.tech.stale_analytics",
                "Elavult analitikai integráció",
                Severity.LOW,
                f"A forrás {len(hits)} elavult analitikai/tracking szolgáltatást hivatkoz, "
                f"amelyek a gyártó (Google) általi élettartam-vég után már nem gyűjtenek adatot. "
                f"Önmagában nem biztonsági kockázat, de jelzi hogy a webhely "
                f"frontend-karbantartása több éve nem történt meg.",
                "Migrálj GA4-re (gtag id G-XXXX) vagy távolítsd el a snippet-et. "
                "Egyúttal érdemes a teljes frontend-karbantartást átnézni.",
                evidence="\n".join(hits),
                confidence=Confidence.VERIFIED,
            )
        )


CSRF_TOKEN_INPUT_NAMES = (
    "csrf", "_token", "authenticity_token", "xsrf",
    "csrfmiddlewaretoken",        # Django
    "__requestverificationtoken", # ASP.NET
    "csrf_token", "csrf-token",
)

CSRF_META_NAME_RE = re.compile(
    r"(?i)^(csrf-token|_csrf|csrf-param|x-csrf-token|csrf|xsrf-token)$"
)


def _check_csrf_token_hint(soup: BeautifulSoup, resp, result: CheckerResult) -> None:
    forms = soup.find_all("form")
    if not forms:
        return
    state_changing = [f for f in forms if (f.get("method") or "GET").upper() == "POST"]
    if not state_changing:
        return

    # Signal 1: hidden CSRF token input in any POST form.
    for f in state_changing:
        for inp in f.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(k in name for k in CSRF_TOKEN_INPUT_NAMES):
                return

    # Signal 2: CSRF meta tag (Rails/Laravel/SPA convention; framework JS reads
    # this and sends X-CSRF-Token header on XHR/fetch).
    meta = soup.find("meta", attrs={"name": CSRF_META_NAME_RE})
    if meta and meta.get("content"):
        return

    # Signal 3: session cookie with SameSite=Strict — browser-level CSRF defense.
    samesite_strict_session = False
    for c in iter_set_cookie_headers(resp):
        lower = c.lower()
        cookie_name = c.split("=", 1)[0].strip()
        if is_likely_session_cookie(cookie_name) and "samesite=strict" in lower:
            samesite_strict_session = True
            break

    if samesite_strict_session:
        result.findings.append(
            Finding(
                "source.csrf.hint",
                "POST űrlap explicit CSRF token nélkül (SameSite=Strict jelenléte mellett)",
                Severity.INFO,
                "A POST űrlapokon nincs explicit CSRF token input vagy meta-tag, de a session cookie SameSite=Strict beállítása böngészőszintű CSRF-védelmet ad. A hiányzó explicit token feltehetően szándékos.",
                "Megerősítésként ellenőrizd, hogy a backend valódi state-changing endpointoknál is támaszkodik-e a SameSite-ra, és van-e Origin/Referer-ellenőrzés mint védelmi réteg.",
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )
    else:
        result.findings.append(
            Finding(
                "source.csrf.hint",
                "Nem látható explicit CSRF védelem POST űrlapon",
                Severity.LOW,
                "A POST űrlapokon nem találtam sem CSRF token input mezőt, sem CSRF meta-tag-et, és a session cookie sem SameSite=Strict. Modern frameworkök (Django, Rails, Laravel, ASP.NET) jellemzően explicit tokent használnak; SPA-k pedig X-CSRF-Token headeren küldenek.",
                "Kézi validáció: nyisd meg az oldalt és ellenőrizd, hogy a backend Origin/Referer-ellenőrzést, header-alapú vagy session-szinkron tokent használ-e. Ha semmi: vezess be CSRF tokent vagy SameSite=Strict session cookie-t.",
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )
