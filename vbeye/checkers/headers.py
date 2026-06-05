from __future__ import annotations

import requests

from vbeye.scoring import CheckerResult, Confidence, Finding, Severity


USER_AGENT = "vbeye/0.1 (+https://github.com/nokufin/vbeye)"

DISCLOSURE_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version",
}


def _norm(headers: dict) -> dict:
    return {k.lower(): v for k, v in headers.items()}


def _check_hsts(h: dict) -> Finding | None:
    v = h.get("strict-transport-security")
    if not v:
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
            Severity.HIGH,
            "Nincs CSP fejléc. XSS esetén nincs böngészőszintű mitigáció, minden inline és külső script lefuthat.",
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
    csp = h.get("content-security-policy", "").lower()
    if "frame-ancestors" in csp:
        return None
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


def _check_disclosure(h: dict) -> list[Finding]:
    out = []
    for key, label in DISCLOSURE_HEADERS.items():
        v = h.get(key)
        if v:
            out.append(
                Finding(
                    f"headers.disclosure.{key}",
                    f"Verziókiadás: {label}",
                    Severity.LOW,
                    f"A `{label}` fejléc szoftvert/verziót szivárogtat, ami célzott exploit kereséshez használható.",
                    "Távolítsd el a fejlécet vagy állítsd üresre a reverse proxyban.",
                    evidence=f"{label}: {v}",
                    confidence=Confidence.VERIFIED,
                )
            )
    return out


def _check_cookies(resp: requests.Response) -> list[Finding]:
    out: list[Finding] = []
    set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    if not set_cookies:
        raw = resp.headers.get("set-cookie")
        if raw:
            set_cookies = [raw]
    is_https = resp.url.startswith("https://")
    for c in set_cookies:
        lower = c.lower()
        name = c.split("=", 1)[0].strip()
        problems = []
        if is_https and "secure" not in lower:
            problems.append("Secure")
        if "httponly" not in lower:
            problems.append("HttpOnly")
        if "samesite=" not in lower:
            problems.append("SameSite")
        if problems:
            out.append(
                Finding(
                    f"headers.cookie.flags",
                    f"Cookie '{name}' hiányzó flag-ek",
                    Severity.MEDIUM,
                    f"A sütő hiányzó attribútumai: {', '.join(problems)}. Ez session lopás / CSRF kockázatot növel.",
                    "Állítsd be a hiányzó flag-eket. SameSite legalább `Lax`, érzékeny sütiknél `Strict`.",
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
            headers={"User-Agent": USER_AGENT},
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

    h = _norm(resp.headers)
    for check in (_check_hsts, _check_csp, _check_xfo, _check_xcto, _check_referrer, _check_permissions):
        f = check(h)
        if f:
            result.findings.append(f)

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
