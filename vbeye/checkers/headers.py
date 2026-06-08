from __future__ import annotations

import re

import requests

from vbeye import __version__
from vbeye.cookies import is_likely_session_cookie, iter_set_cookie_headers
from vbeye.scoring import CheckerResult, Confidence, Finding, Severity


VERSION_RE = re.compile(r"\d+\.\d+")

PHP_VERSION_RE = re.compile(r"(?i)PHP/(\d+)\.(\d+)(?:\.(\d+))?")

# PHP support windows per php.net/supported-versions
# As of 2026 — security support ENDED for these versions, no further patches.
# Update this list periodically as PHP versions reach EoL.
PHP_EOL_CRITICAL = (
    (5, 0), (5, 1), (5, 2), (5, 3), (5, 4), (5, 5), (5, 6),  # all 5.x EoL since 2018
    (7, 0), (7, 1), (7, 2), (7, 3), (7, 4),                   # all 7.x EoL by 2022
    (8, 0),                                                    # 8.0 EoL Nov 2023
)
PHP_EOL_HIGH = (
    (8, 1),   # EoL Nov 2024
    (8, 2),   # EoL Dec 2025
)

FRAME_ANCESTORS_RE = re.compile(r"(?i)frame-ancestors\s+([^;]+)")

# CSP source values that allow ANY origin to embed — these don't protect against clickjacking.
PERMISSIVE_FA_SOURCES = {"*", "http:", "https:", "ws:", "wss:", "data:", "blob:", "filesystem:"}


def _frame_ancestors_protects(value: str) -> bool:
    tokens = value.lower().split()
    if not tokens:
        return False
    if tokens == ["'none'"]:
        return True
    if any(t in PERMISSIVE_FA_SOURCES for t in tokens):
        return False
    return True


USER_AGENT = f"vbeye/{__version__} (+https://github.com/nokufin/vbeye)"

REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "hu-HU,hu;q=0.9,en;q=0.8",
}

DISCLOSURE_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
}


def _norm(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def _check_hsts(h: dict, is_https: bool) -> Finding | None:
    v = h.get("strict-transport-security")
    if not v:
        if not is_https:
            # HSTS HTTP-n értelmetlen — a böngészők figyelmen kívül hagyják.
            # A no_https_redirect finding már lefedi a tényleges kockázatot.
            return None
        return Finding(
            "headers.hsts.missing",
            "HSTS hiányzik",
            Severity.HIGH,
            "Nincs Strict-Transport-Security fejléc. A böngészők nem kényszerítik HTTPS használatát, így SSL-stripping támadás lehetséges.",
            "Adj hozzá `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` fejlécet.",
            confidence=Confidence.VERIFIED,
        )
    parts = [p.strip().lower() for p in v.split(";")]
    max_age = 0
    for p in parts:
        if p.startswith("max-age="):
            try:
                max_age = int(p.split("=", 1)[1])
            except ValueError:
                pass
    if max_age < 15552000:  # 180 nap
        return Finding(
            "headers.hsts.weak",
            "HSTS max-age túl rövid",
            Severity.MEDIUM,
            f"A HSTS max-age értéke {max_age} sec, ami a legtöbb böngésző elvárása alatt van (min. 6 hónap).",
            "Állítsd legalább 15552000 (180 nap), preload listához 31536000 (1 év) szükséges.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    if "includesubdomains" not in parts:
        return Finding(
            "headers.hsts.no_subdomains",
            "HSTS includeSubDomains hiányzik",
            Severity.LOW,
            "Az aldomainek nincsenek védve HSTS-szel, ami sub-domain takeover támadásnál hasznosítható.",
            "Egészítsd ki a fejlécet `includeSubDomains` direktívával.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_csp(h: dict) -> Finding | None:
    v = h.get("content-security-policy")
    if not v:
        return Finding(
            "headers.csp.missing",
            "Content-Security-Policy hiányzik",
            Severity.MEDIUM,
            "Nincs CSP fejléc. Önmagában nem jelent exploit-ot, de XSS esetén nincs böngészőszintű mitigációs réteg.",
            "Vezess be CSP-t legalább `default-src 'self'` alappal, és iteratív szigorítással.",
            confidence=Confidence.VERIFIED,
        )
    lower = v.lower()
    risky = []
    if "'unsafe-inline'" in lower:
        risky.append("unsafe-inline")
    if "'unsafe-eval'" in lower:
        risky.append("unsafe-eval")
    if " * " in f" {lower} " or lower.strip().endswith(" *") or "src *" in lower:
        risky.append("wildcard source")
    if risky:
        return Finding(
            "headers.csp.weak",
            "CSP gyenge direktívákat tartalmaz",
            Severity.MEDIUM,
            f"A CSP enged: {', '.join(risky)}. Ezek lényegében kioltják a CSP védelmét.",
            "Cseréld le nonce-/hash-alapú megoldásra, és kerüld a wildcard source-okat.",
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
            "CSP frame-ancestors túl megengedő",
            Severity.MEDIUM,
            f"A `frame-ancestors {fa_value}` direktíva engedélyezi tetszőleges origin-ből az iframe beágyazást, így nem ad clickjacking-védelmet.",
            "Szigorítsd `'none'`, `'self'` vagy konkrét megbízható origin listára.",
            evidence=f"frame-ancestors {fa_value}",
            confidence=Confidence.VERIFIED,
        )
    v = h.get("x-frame-options")
    if not v:
        return Finding(
            "headers.xfo.missing",
            "X-Frame-Options / frame-ancestors hiányzik",
            Severity.MEDIUM,
            "Clickjacking elleni védelem nélkül az oldal beágyazható iframe-be.",
            "Adj hozzá `X-Frame-Options: DENY` vagy CSP `frame-ancestors 'none'` direktívát.",
            confidence=Confidence.VERIFIED,
        )
    if v.upper() not in ("DENY", "SAMEORIGIN"):
        return Finding(
            "headers.xfo.invalid",
            "X-Frame-Options érvénytelen érték",
            Severity.LOW,
            f"Az X-Frame-Options értéke `{v}` — az ALLOW-FROM elavult, csak DENY/SAMEORIGIN érvényes.",
            "Cseréld `DENY`-re vagy `SAMEORIGIN`-ra.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_xcto(h: dict) -> Finding | None:
    v = h.get("x-content-type-options")
    if not v or v.lower() != "nosniff":
        return Finding(
            "headers.xcto.missing",
            "X-Content-Type-Options nosniff hiányzik",
            Severity.LOW,
            "A böngésző MIME-snifolhatja a tartalmat, ami pl. képnek álcázott script futtatását teheti lehetővé.",
            "Adj hozzá `X-Content-Type-Options: nosniff` fejlécet.",
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_referrer(h: dict) -> Finding | None:
    v = h.get("referrer-policy")
    if not v:
        return Finding(
            "headers.referrer.missing",
            "Referrer-Policy hiányzik",
            Severity.LOW,
            "Külső linkeken alapértelmezetten szivároghatnak útvonalak és query paraméterek.",
            "Állítsd `strict-origin-when-cross-origin`-ra vagy szigorúbbra.",
            confidence=Confidence.VERIFIED,
        )
    weak = {"unsafe-url", "no-referrer-when-downgrade", ""}
    if v.lower() in weak:
        return Finding(
            "headers.referrer.weak",
            "Referrer-Policy túl megengedő",
            Severity.LOW,
            f"A `{v}` policy érzékeny URL adatokat szivárogtathat más originekre.",
            "Használj `strict-origin-when-cross-origin` vagy `no-referrer` értéket.",
            evidence=v,
            confidence=Confidence.VERIFIED,
        )
    return None


def _check_permissions(h: dict) -> Finding | None:
    if not h.get("permissions-policy") and not h.get("feature-policy"):
        return Finding(
            "headers.permissions.missing",
            "Permissions-Policy hiányzik",
            Severity.INFO,
            "Nincs explicit korlátozás a böngésző feature-ekre (kamera, mikrofon, geolocation, stb.).",
            "Definiálj minimum-policy-t, pl. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
            confidence=Confidence.VERIFIED,
        )
    return None


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
            f"Elavult PHP verzió ({version}) — biztonsági támogatás megszűnt",
            Severity.CRITICAL,
            f"A szerver PHP {version}-et használ az X-Powered-By fejléc alapján. Ez a verzió a "
            f"php.net hivatalos támogatása alól kikerült, vagyis ismert sebezhetőségekre "
            f"a felfedezésük óta nem érkezik javítás. Egy aktuális CVE-publikálás után a webhely "
            f"a publikus exploit-okkal szemben azonnal kitett.",
            "Frissítsd a PHP-t aktuálisan támogatott verzióra (jelenleg 8.3+). Kompatibilitási "
            "változások miatt staging környezetben teszteld először.",
            evidence=f"X-Powered-By: {v}",
            confidence=Confidence.VERIFIED,
        )
    if branch in PHP_EOL_HIGH:
        return Finding(
            "headers.tech.php_eol",
            f"Frissen elavult PHP verzió ({version}) — biztonsági támogatás lejárt",
            Severity.HIGH,
            f"A szerver PHP {version}-et használ, ami a php.net hivatalos biztonsági támogatás "
            f"alól nemrég került ki. Új CVE-k esetén már nem kap patch-et.",
            "Frissítsd a PHP-t aktuálisan támogatott verzióra (8.3+). Tervezz upgrade-et "
            "rövid határidővel.",
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
        # PHP-specific lifecycle handled by _check_php_version — skip generic disclosure
        # to avoid emitting both a LOW "verziókiadás" and a CRITICAL EoL finding.
        if key == "x-powered-by" and PHP_VERSION_RE.search(v):
            continue
        has_version = bool(VERSION_RE.search(v))
        if has_version:
            out.append(
                Finding(
                    f"headers.disclosure.{key}",
                    f"Verziókiadás: {label}",
                    Severity.LOW,
                    f"A `{label}` fejléc konkrét verziószámot szivárogtat, ami célzott exploit kereséshez használható.",
                    "Távolítsd el a fejlécet vagy állítsd üresre a reverse proxyban.",
                    evidence=f"{label}: {v}",
                    confidence=Confidence.VERIFIED,
                )
            )
        else:
            out.append(
                Finding(
                    f"headers.disclosure.{key}",
                    f"Szoftver-azonosítás: {label}",
                    Severity.INFO,
                    f"A `{label}` fejléc megnevezi a kiszolgáló szoftvert verziószám nélkül. Ez önmagában nem jelent közvetlen kihasználható kockázatot, de felderítést könnyíti.",
                    "Ha nincs üzemeltetési indok, érdemes a fejlécet eltávolítani vagy semleges értékre cserélni.",
                    evidence=f"{label}: {v}",
                    confidence=Confidence.VERIFIED,
                )
            )
    return out


def _check_cookies(resp: requests.Response) -> list[Finding]:
    out: list[Finding] = []
    set_cookies = iter_set_cookie_headers(resp)
    is_https = resp.url.startswith("https://")
    for c in set_cookies:
        lower = c.lower()
        name = c.split("=", 1)[0].strip()
        is_session = is_likely_session_cookie(name)

        # SameSite=None requires Secure (RFC 6265bis) — modern browsers reject the
        # cookie outright otherwise. Treat as a distinct misconfiguration.
        samesite_none_insecure = ("samesite=none" in lower) and ("secure" not in lower)

        problems = []
        if samesite_none_insecure:
            problems.append("Secure (SameSite=None megköveteli)")
        elif is_https and "secure" not in lower:
            problems.append("Secure")
        if "httponly" not in lower:
            problems.append("HttpOnly")
        if "samesite=" not in lower:
            problems.append("SameSite")

        if not problems:
            continue

        # Session cookies are auth boundary — missing flags = direct hijack path.
        # 2+ missing flags is a full hijack trifecta (TLS-downgrade + XSS + CSRF
        # all viable) → CRITICAL, real-risk bypass. 1 missing flag is HIGH.
        if is_session:
            check_id = "headers.cookie.session_flags"
            if len(problems) >= 2:
                severity = Severity.CRITICAL
                label = "Session-szerű cookie"
                risk = (
                    "egyidejű TLS-downgrade, XSS és CSRF alapú session-hijack lehetőséget ad — "
                    "az érintett munkamenet teljes átvételére alkalmas vektor"
                )
            else:
                severity = Severity.HIGH
                label = "Session-szerű cookie"
                risk = "session-lopás vagy CSRF kockázatot növel"
        elif samesite_none_insecure:
            check_id = "headers.cookie.flags"
            severity = Severity.MEDIUM
            label = "Cookie"
            risk = "modern böngészők a sütit elutasítják, ami funkcionális hibához vezethet"
        else:
            check_id = "headers.cookie.flags"
            severity = Severity.LOW
            label = "Cookie"
            risk = "adatvédelmi és cross-site visszaélési szempontból érdemes javítani"

        out.append(
            Finding(
                check_id,
                f"{label} '{name}' hiányzó / hibás flag-ek",
                severity,
                f"A `{name}` cookie attribútum-hibái: {', '.join(problems)}. Ez {risk}.",
                "Állítsd be a hiányzó flag-eket. SameSite legalább `Lax`, érzékeny sütiknél `Strict`. SameSite=None csak Secure mellett érvényes.",
                evidence=c[:200],
                confidence=Confidence.VERIFIED,
            )
        )
    return out


def run(url: str, timeout: int = 10) -> CheckerResult:
    result = CheckerResult(name="headers")
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

    result.meta["final_url"] = resp.url
    result.meta["status_code"] = resp.status_code
    result.meta["headers"] = dict(resp.headers)

    # ha eredetileg http volt és átirányít https-re, az jó jel
    if url.startswith("http://") and resp.url.startswith("http://"):
        result.findings.append(
            Finding(
                "headers.no_https_redirect",
                "Nincs HTTPS átirányítás",
                Severity.HIGH,
                "A HTTP kérés nem irányít HTTPS-re, így a forgalom alapból titkosítatlan.",
                "Konfigurálj 301-es átirányítást a HTTPS verzióra, és kapcsold be a HSTS-t.",
                evidence=f"start: {url} → final: {resp.url}",
                confidence=Confidence.VERIFIED,
            )
        )

    # cross-host redirect: ha az eredetileg lekért host eltér a végső host-tól,
    # akkor a HSTS rollout sebezhető (a bare domain HSTS-t soha nem kap).
    try:
        from urllib.parse import urlparse as _urlparse
        orig_host = (_urlparse(url).hostname or "").lower()
        final_host = (_urlparse(resp.url).hostname or "").lower()
        if orig_host and final_host and orig_host != final_host:
            chain = " → ".join(
                f"{h.status_code} {h.url}" for h in resp.history
            ) + f" → {resp.status_code} {resp.url}"
            result.findings.append(
                Finding(
                    "headers.redirect.cross_host",
                    f"Cross-host átirányítás ({orig_host} → {final_host})",
                    Severity.MEDIUM,
                    f"A `{orig_host}` host átirányít a `{final_host}` host-ra. Ez a HSTS rollout "
                    f"szempontjából problémás: a HSTS fejléc a végső host-on érvényesül, de a bare/eredeti "
                    f"domain-en soha nem kerül beállításra. Ha valaki HTTP-vel kezdi a bare domain-en, "
                    f"a kezdeti HTTP kérés MITM-támadás célpontja lehet.",
                    "Az átirányítás célja legyen ugyanaz a host: először HTTP→HTTPS azonos hostnál, "
                    "majd csak utána host-csere. Vagy állíts be HSTS-t mindkét host-on.",
                    evidence=chain,
                    confidence=Confidence.VERIFIED,
                )
            )
    except Exception:
        pass

    h = _norm(resp.headers)
    is_https_final = resp.url.startswith("https://")

    hsts_finding = _check_hsts(h, is_https_final)
    if hsts_finding:
        result.findings.append(hsts_finding)

    for check in (_check_csp, _check_xfo, _check_xcto, _check_referrer, _check_permissions):
        f = check(h)
        if f:
            result.findings.append(f)

    php_finding = _check_php_version(h)
    if php_finding:
        result.findings.append(php_finding)

    result.findings.extend(_check_disclosure(h))
    result.findings.extend(_check_cookies(resp))

    if not result.findings:
        result.findings.append(
            Finding(
                "headers.ok",
                "Security headers rendben",
                Severity.OK,
                "Minden fontos security header beállítva, nincs nyilvánvaló hiányosság.",
                confidence=Confidence.VERIFIED,
            )
        )

    return result
