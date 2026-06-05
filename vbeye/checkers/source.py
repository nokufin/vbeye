from __future__ import annotations

import math
import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from vbeye.scoring import CheckerResult, Confidence, Finding, Severity


USER_AGENT = "vbeye/0.1"

# Format-specific patterns — high precision, low false-positive rate.
HIGH_CONFIDENCE_SECRETS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Slack token", re.compile(r"xox[abprs]-[0-9A-Za-z\-]{10,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("GitHub PAT", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9]{24,}\b")),
]

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


def _absolute(base: str, href: str) -> str:
    return urljoin(base, href)


def _is_external(base: str, href: str) -> bool:
    try:
        base_host = urlparse(base).hostname or ""
        ref_host = urlparse(_absolute(base, href)).hostname or ""
        return ref_host != "" and ref_host != base_host
    except Exception:
        return False


def run(url: str, timeout: int = 10) -> CheckerResult:
    result = CheckerResult(name="source")
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.RequestException as e:
        result.error = f"HTTP lekérés sikertelen: {e}"
        return result

    final_url = resp.url
    is_https = final_url.startswith("https://")
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
    _check_csrf_token_hint(soup, result)

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


def _check_mixed_content(soup: BeautifulSoup, base: str, is_https: bool, result: CheckerResult) -> None:
    if not is_https:
        return
    mixed = []
    for tag, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src"), ("video", "src"), ("audio", "src")):
        for el in soup.find_all(tag):
            v = el.get(attr)
            if v and v.startswith("http://"):
                mixed.append(f"{tag} {attr}={v}")
    if mixed:
        result.findings.append(
            Finding(
                "source.mixed_content",
                "Mixed content (HTTP erőforrás HTTPS oldalon)",
                Severity.HIGH,
                f"{len(mixed)} darab HTTP erőforrás a HTTPS oldalon. A böngészők blokkolják vagy figyelmeztetnek; MITM esetén injektálható.",
                "Cseréld a HTTP URL-eket HTTPS-re, vagy használj protokoll-relatív URL-t.",
                evidence="\n".join(mixed[:10]),
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
    if verified_hits:
        result.findings.append(
            Finding(
                "source.secret.exposed",
                "Konkrét formátumú titok a HTML-ben",
                Severity.CRITICAL,
                "A kiszolgált tartalom formátum-specifikus titok-mintát tartalmaz (AWS / Google / Slack / GitHub / Stripe kulcs vagy PEM private key block). Azonnal rotálandó, ha valódi.",
                "Rotáld a kulcsot, töröld a HTML-ből, mozgasd backendbe / env változóba.",
                evidence="\n".join(verified_hits),
                confidence=Confidence.VERIFIED,
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
    for src in sources:
        for lib, patterns in VULNERABLE_LIBS.items():
            for pat, version_label, note in patterns:
                if pat.search(src):
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


def _check_csrf_token_hint(soup: BeautifulSoup, result: CheckerResult) -> None:
    forms = soup.find_all("form")
    if not forms:
        return
    state_changing = [f for f in forms if (f.get("method") or "GET").upper() == "POST"]
    if not state_changing:
        return
    has_token = False
    for f in state_changing:
        for inp in f.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(k in name for k in ("csrf", "_token", "authenticity_token", "xsrf")):
                has_token = True
                break
        if has_token:
            break
    if not has_token:
        result.findings.append(
            Finding(
                "source.csrf.hint",
                "Nem látható CSRF token POST űrlapon",
                Severity.LOW,
                "A POST űrlapokon nem találtam tipikus CSRF token mezőt. Lehet, hogy header/cookie alapú a védelem — kézi ellenőrzés kell.",
                "Ellenőrizd hogy van CSRF védelem (token vagy SameSite=Strict cookie + origin check).",
                confidence=Confidence.REQUIRES_MANUAL_VALIDATION,
            )
        )
