from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from vbeye.scoring import CheckerResult, Finding, Severity


def _parse_host_port(url: str) -> tuple[str, int]:
    p = urlparse(url if "://" in url else f"https://{url}")
    host = p.hostname or url
    port = p.port or (443 if (p.scheme or "https") == "https" else 80)
    return host, port


def run(url: str, timeout: int = 15) -> CheckerResult:
    result = CheckerResult(name="ssl")

    if not url.startswith("https://") and "://" not in url:
        url = f"https://{url}"
    if not url.startswith("https://"):
        result.findings.append(
            Finding(
                "ssl.no_tls",
                "Nincs HTTPS",
                Severity.CRITICAL,
                "A célpont HTTP-n érhető el, nincs TLS — minden forgalom titkosítatlan.",
                "Telepíts érvényes tanúsítványt és kényszerítsd a HTTPS használatát.",
            )
        )
        return result

    try:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
            ServerScanStatusEnum,
            ServerHostnameCouldNotBeResolved,
        )
    except ImportError as e:
        result.error = f"sslyze nincs telepítve: {e}"
        return result

    host, port = _parse_host_port(url)

    try:
        location = ServerNetworkLocation(hostname=host, port=port)
    except ServerHostnameCouldNotBeResolved as e:
        result.error = f"Hostnév nem feloldható: {e}"
        return result

    scan_commands = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    }
    request = ServerScanRequest(server_location=location, scan_commands=scan_commands)

    scanner = Scanner()
    scanner.queue_scans([request])

    server_result = None
    for r in scanner.get_results():
        server_result = r
        break

    if server_result is None or server_result.scan_status != ServerScanStatusEnum.COMPLETED:
        result.error = "Az SSL scan nem fejeződött be (csatlakozási hiba)."
        return result

    sr = server_result.scan_result
    result.meta["hostname"] = host
    result.meta["port"] = port

    _eval_certificate(sr, result)
    _eval_protocols(sr, result)

    if not result.findings:
        result.findings.append(
            Finding(
                "ssl.ok",
                "TLS konfiguráció rendben",
                Severity.OK,
                "Nem találtam ismert TLS-szintű hiányosságot.",
            )
        )

    return result


def _eval_certificate(sr, result: CheckerResult) -> None:
    cert_info = sr.certificate_info.result if sr.certificate_info and sr.certificate_info.result else None
    if not cert_info:
        return
    deployments = cert_info.certificate_deployments
    if not deployments:
        return
    dep = deployments[0]

    leaf = dep.received_certificate_chain[0] if dep.received_certificate_chain else None
    if leaf is not None:
        now = datetime.now(timezone.utc)
        not_after = leaf.not_valid_after_utc if hasattr(leaf, "not_valid_after_utc") else leaf.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - now).days
        result.meta["cert_not_after"] = not_after.isoformat()
        result.meta["cert_subject"] = leaf.subject.rfc4514_string()
        result.meta["cert_issuer"] = leaf.issuer.rfc4514_string()

        if days_left < 0:
            result.findings.append(
                Finding(
                    "ssl.cert.expired",
                    "A tanúsítvány lejárt",
                    Severity.CRITICAL,
                    f"A tanúsítvány lejárt {abs(days_left)} napja ({not_after.date()}).",
                    "Újítsd meg azonnal (pl. Let's Encrypt + automatikus renew).",
                )
            )
        elif days_left < 14:
            result.findings.append(
                Finding(
                    "ssl.cert.expiring",
                    "A tanúsítvány hamarosan lejár",
                    Severity.HIGH,
                    f"A tanúsítvány {days_left} nap múlva lejár.",
                    "Indítsd a megújítást, ellenőrizd az automatikus renew folyamatot.",
                )
            )
        elif days_left < 30:
            result.findings.append(
                Finding(
                    "ssl.cert.expiring_soon",
                    "Tanúsítvány <30 nap",
                    Severity.MEDIUM,
                    f"A tanúsítvány {days_left} nap múlva lejár.",
                    "Tervezd a megújítást.",
                )
            )

        pub = leaf.public_key()
        _eval_public_key(pub, result)

    if not dep.verified_certificate_chain:
        result.findings.append(
            Finding(
                "ssl.cert.untrusted",
                "Lánc nem hitelesíthető",
                Severity.HIGH,
                "A tanúsítványlánc nem ellenőrizhető a böngészők megbízható CA store-jával (self-signed vagy hibás közbenső CA).",
                "Telepítsd a közbenső CA tanúsítványokat, vagy szerezz be nyilvános CA-tól újat.",
            )
        )

    if hasattr(dep, "leaf_certificate_subject_matches_hostname") and not dep.leaf_certificate_subject_matches_hostname:
        result.findings.append(
            Finding(
                "ssl.cert.hostname_mismatch",
                "Hostnév nem egyezik",
                Severity.HIGH,
                "A tanúsítvány Subject/SAN mezője nem fedi a vizsgált hostnevet.",
                "Adj ki tanúsítványt a megfelelő hostnévre, vagy javítsd a virtual host konfigot.",
            )
        )


def _eval_public_key(pub, result: CheckerResult) -> None:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    key_size = getattr(pub, "key_size", None)
    if isinstance(pub, rsa.RSAPublicKey):
        result.meta["cert_key_type"] = "RSA"
        result.meta["cert_key_size"] = key_size
        if key_size and key_size < 2048:
            result.findings.append(
                Finding(
                    "ssl.cert.weak_key",
                    f"Gyenge RSA kulcsméret: {key_size} bit",
                    Severity.HIGH,
                    "Az RSA kulcs mérete a jelenlegi ajánlás alatt van (min. 2048).",
                    "Generálj 2048+ bites RSA vagy ECDSA P-256 kulcsot.",
                )
            )
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        curve_name = pub.curve.name
        result.meta["cert_key_type"] = f"ECDSA ({curve_name})"
        result.meta["cert_key_size"] = key_size
        if key_size and key_size < 256:
            result.findings.append(
                Finding(
                    "ssl.cert.weak_key",
                    f"Gyenge ECDSA görbe: {curve_name} ({key_size} bit)",
                    Severity.HIGH,
                    "Az elliptikus görbe a jelenlegi ajánlás alatt van (min. P-256).",
                    "Cseréld P-256 vagy P-384 görbére.",
                )
            )
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        alg = "Ed25519" if isinstance(pub, ed25519.Ed25519PublicKey) else "Ed448"
        result.meta["cert_key_type"] = alg
    elif isinstance(pub, dsa.DSAPublicKey):
        result.meta["cert_key_type"] = "DSA"
        result.meta["cert_key_size"] = key_size
        result.findings.append(
            Finding(
                "ssl.cert.dsa_deprecated",
                "Elavult DSA kulcs",
                Severity.HIGH,
                "A DSA aláírási algoritmus elavult, modern böngészők és kliensek nem támogatják megbízhatóan.",
                "Cseréld RSA 2048+ vagy ECDSA P-256 kulcsra.",
            )
        )
    else:
        result.meta["cert_key_type"] = type(pub).__name__
        if key_size is not None:
            result.meta["cert_key_size"] = key_size


def _eval_protocols(sr, result: CheckerResult) -> None:
    enabled: list[str] = []
    deprecated_attrs = {
        "ssl_2_0_cipher_suites": ("SSLv2", Severity.CRITICAL),
        "ssl_3_0_cipher_suites": ("SSLv3", Severity.HIGH),
        "tls_1_0_cipher_suites": ("TLS 1.0", Severity.MEDIUM),
        "tls_1_1_cipher_suites": ("TLS 1.1", Severity.MEDIUM),
    }
    for attr, (label, sev) in deprecated_attrs.items():
        scan = getattr(sr, attr, None)
        if scan and scan.result and scan.result.accepted_cipher_suites:
            enabled.append(label)
            result.findings.append(
                Finding(
                    f"ssl.protocol.{attr}",
                    f"Elavult protokoll támogatott: {label}",
                    sev,
                    f"A szerver elfogadja a {label} protokollt, amiben ismert kriptográfiai hibák vannak (pl. POODLE, BEAST).",
                    f"Tiltsd le a {label}-t, csak TLS 1.2 és 1.3 maradjon.",
                )
            )

    has_modern = False
    for attr in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
        scan = getattr(sr, attr, None)
        if scan and scan.result and scan.result.accepted_cipher_suites:
            has_modern = True
            label = "TLS 1.2" if "1_2" in attr else "TLS 1.3"
            enabled.append(label)

    result.meta["enabled_protocols"] = enabled

    if not has_modern:
        result.findings.append(
            Finding(
                "ssl.protocol.no_modern",
                "Nincs modern TLS protokoll",
                Severity.CRITICAL,
                "Sem TLS 1.2, sem TLS 1.3 nincs engedélyezve.",
                "Engedélyezd a TLS 1.2-t és 1.3-at.",
            )
        )

    tls12 = getattr(sr, "tls_1_2_cipher_suites", None)
    if tls12 and tls12.result:
        weak = []
        for cs in tls12.result.accepted_cipher_suites:
            name = cs.cipher_suite.name
            if any(k in name for k in ("_RC4_", "_3DES_", "_NULL_", "_EXPORT_", "_DES_CBC_", "_anon_")):
                weak.append(name)
        if weak:
            result.findings.append(
                Finding(
                    "ssl.cipher.weak",
                    "Gyenge cipher suite-ek engedélyezve",
                    Severity.HIGH,
                    f"A TLS 1.2 rétegen gyenge cipher-ek elérhetők: {', '.join(weak[:5])}{'…' if len(weak) > 5 else ''}",
                    "Tiltsd le az RC4, 3DES, NULL, EXPORT és anon cipher suite-eket.",
                )
            )


