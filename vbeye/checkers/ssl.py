from __future__ import annotations

import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

from vbeye.context import ScanContext
from vbeye.scoring import CheckerResult, Confidence, Finding, Severity

warnings.filterwarnings("ignore", module=r"sslyze\.")

NAME = "ssl"

DEPRECATED_PROTOCOLS = {
    "ssl_2_0_cipher_suites": ("SSLv2", Severity.CRITICAL),
    "ssl_3_0_cipher_suites": ("SSLv3", Severity.HIGH),
    "tls_1_0_cipher_suites": ("TLS 1.0", Severity.MEDIUM),
    "tls_1_1_cipher_suites": ("TLS 1.1", Severity.MEDIUM),
}

WEAK_CIPHER_SCAN_ATTRS = {
    "ssl_3_0_cipher_suites": "SSLv3",
    "tls_1_0_cipher_suites": "TLS 1.0",
    "tls_1_1_cipher_suites": "TLS 1.1",
    "tls_1_2_cipher_suites": "TLS 1.2",
}

WEAK_CIPHER_MARKERS = ("_RC4_", "_3DES_", "_NULL_", "_EXPORT_", "_DES_CBC_", "_anon_")

NETWORK_MAX_RETRIES = 2


def _target_host_port(ctx: ScanContext) -> tuple[str, int]:
    if ctx.page.response is not None:
        parsed = urlparse(ctx.page.final_url)
        host = ctx.page.final_host or ctx.host
    else:
        parsed = urlparse(ctx.url)
        host = ctx.host
    port = parsed.port if parsed.scheme == "https" and parsed.port else 443
    return host, port


def _connectivity_error_text(server_result) -> str:
    trace = getattr(server_result, "connectivity_error_trace", None)
    if trace is None:
        return "no TLS connectivity"
    if hasattr(trace, "format_exception_only"):
        return "".join(trace.format_exception_only()).strip() or "no TLS connectivity"
    return str(trace) or "no TLS connectivity"


def _scan(host: str, port: int, timeout: int):
    from sslyze import (
        ScanCommand,
        Scanner,
        ServerNetworkConfiguration,
        ServerNetworkLocation,
        ServerScanRequest,
    )

    location = ServerNetworkLocation(hostname=host, port=port)
    network_config = ServerNetworkConfiguration(
        tls_server_name_indication=host,
        network_timeout=max(1, int(timeout)),
        network_max_retries=NETWORK_MAX_RETRIES,
    )
    request = ServerScanRequest(
        server_location=location,
        network_configuration=network_config,
        scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        },
    )
    scanner = Scanner()
    scanner.queue_scans([request])
    for server_result in scanner.get_results():
        return server_result
    return None


def run(ctx: ScanContext) -> CheckerResult:
    result = CheckerResult(name=NAME)
    host, port = _target_host_port(ctx)
    result.meta["hostname"] = host
    result.meta["port"] = port

    if not host:
        result.error = "No hostname to scan."
        return result

    try:
        from sslyze import ServerHostnameCouldNotBeResolved, ServerScanStatusEnum
    except ImportError as e:
        result.error = f"sslyze is not installed: {e}"
        return result

    try:
        server_result = _scan(host, port, ctx.timeout)
    except ServerHostnameCouldNotBeResolved as e:
        result.error = f"Hostname could not be resolved: {e}"
        return result
    except Exception as e:
        result.error = f"TLS scan failed: {type(e).__name__}: {e}"
        return result

    if server_result is None:
        result.error = "TLS scan returned no result."
        return result

    if server_result.scan_status != ServerScanStatusEnum.COMPLETED or server_result.scan_result is None:
        reason = _connectivity_error_text(server_result)
        if ctx.page.ok and not ctx.page.is_https:
            result.findings.append(
                Finding(
                    "ssl.no_tls",
                    "HTTPS not available",
                    Severity.CRITICAL,
                    "The site is served over plain HTTP and no TLS service answers on the HTTPS port. "
                    "All traffic, including credentials and session cookies, is sent unencrypted.",
                    "Deploy a valid certificate, serve the site over HTTPS and redirect all HTTP requests to it.",
                    evidence=f"{host}:{port} - {reason}",
                    confidence=Confidence.VERIFIED,
                )
            )
        else:
            result.error = f"TLS connection to {host}:{port} failed: {reason}"
        return result

    try:
        sr = server_result.scan_result
        _eval_certificate(sr, result)
        _eval_protocols(sr, result)
    except Exception as e:
        result.error = f"TLS result evaluation failed: {type(e).__name__}: {e}"
        return result

    if not result.findings:
        result.findings.append(
            Finding(
                "ssl.ok",
                "TLS configuration OK",
                Severity.OK,
                "No known TLS-level weaknesses were detected.",
                confidence=Confidence.VERIFIED,
            )
        )
    return result


def _not_after(cert) -> datetime:
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _eval_certificate(sr, result: CheckerResult) -> None:
    attempt = getattr(sr, "certificate_info", None)
    cert_info = attempt.result if attempt is not None else None
    if not cert_info or not cert_info.certificate_deployments:
        return
    dep = cert_info.certificate_deployments[0]

    leaf = dep.received_certificate_chain[0] if dep.received_certificate_chain else None
    if leaf is not None:
        not_after = _not_after(leaf)
        days_left = (not_after - datetime.now(timezone.utc)).days
        result.meta["cert_not_after"] = not_after.isoformat()
        result.meta["cert_subject"] = leaf.subject.rfc4514_string()
        result.meta["cert_issuer"] = leaf.issuer.rfc4514_string()
        evidence = f"notAfter: {not_after.isoformat()}"

        if days_left < 0:
            result.findings.append(
                Finding(
                    "ssl.cert.expired",
                    "Certificate expired",
                    Severity.CRITICAL,
                    f"The certificate expired {abs(days_left)} day(s) ago ({not_after.date()}). "
                    f"Browsers show a blocking security warning.",
                    "Renew the certificate immediately and automate renewal (e.g. ACME / Let's Encrypt).",
                    evidence=evidence,
                    confidence=Confidence.VERIFIED,
                )
            )
        elif days_left < 14:
            result.findings.append(
                Finding(
                    "ssl.cert.expiring",
                    "Certificate expires within 14 days",
                    Severity.HIGH,
                    f"The certificate expires in {days_left} day(s).",
                    "Renew the certificate now and verify that automated renewal works.",
                    evidence=evidence,
                    confidence=Confidence.VERIFIED,
                )
            )
        elif days_left < 30:
            result.findings.append(
                Finding(
                    "ssl.cert.expiring_soon",
                    "Certificate expires within 30 days",
                    Severity.MEDIUM,
                    f"The certificate expires in {days_left} day(s).",
                    "Schedule the renewal.",
                    evidence=evidence,
                    confidence=Confidence.VERIFIED,
                )
            )

        _eval_public_key(leaf.public_key(), result)

    if not dep.verified_certificate_chain:
        result.findings.append(
            Finding(
                "ssl.cert.untrusted",
                "Certificate chain not trusted",
                Severity.HIGH,
                "The certificate chain does not validate against public trust stores "
                "(self-signed certificate or missing/invalid intermediate CA).",
                "Serve the complete intermediate chain or obtain a certificate from a publicly trusted CA.",
                confidence=Confidence.VERIFIED,
            )
        )

    if getattr(dep, "leaf_certificate_subject_matches_hostname", True) is False:
        host = result.meta.get("hostname", "the scanned host")
        result.findings.append(
            Finding(
                "ssl.cert.hostname_mismatch",
                "Certificate does not match hostname",
                Severity.HIGH,
                f"The certificate subject / SAN entries do not cover {host}.",
                "Issue a certificate that covers this hostname or fix the virtual host configuration.",
                evidence=result.meta.get("cert_subject", ""),
                confidence=Confidence.VERIFIED,
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
                    f"Weak RSA key: {key_size} bit",
                    Severity.HIGH,
                    "The RSA key is shorter than the 2048-bit minimum.",
                    "Issue a new certificate with an RSA 2048+ or ECDSA P-256 key.",
                    evidence=f"RSA {key_size} bit",
                    confidence=Confidence.VERIFIED,
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
                    f"Weak ECDSA curve: {curve_name} ({key_size} bit)",
                    Severity.HIGH,
                    "The elliptic curve is weaker than the P-256 minimum.",
                    "Issue a new certificate on P-256 or P-384.",
                    evidence=f"ECDSA curve={curve_name}, {key_size} bit",
                    confidence=Confidence.VERIFIED,
                )
            )
    elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        result.meta["cert_key_type"] = "Ed25519" if isinstance(pub, ed25519.Ed25519PublicKey) else "Ed448"
    elif isinstance(pub, dsa.DSAPublicKey):
        result.meta["cert_key_type"] = "DSA"
        result.meta["cert_key_size"] = key_size
        result.findings.append(
            Finding(
                "ssl.cert.dsa_deprecated",
                "Deprecated DSA key",
                Severity.HIGH,
                "DSA certificate keys are deprecated and not reliably supported by modern clients.",
                "Issue a new certificate with an RSA 2048+ or ECDSA P-256 key.",
                evidence=f"DSA {key_size} bit",
                confidence=Confidence.VERIFIED,
            )
        )
    else:
        result.meta["cert_key_type"] = type(pub).__name__
        if key_size is not None:
            result.meta["cert_key_size"] = key_size


def _accepted(sr, attr: str) -> list:
    attempt = getattr(sr, attr, None)
    if attempt is None or attempt.result is None:
        return []
    return list(attempt.result.accepted_cipher_suites or [])


def _eval_protocols(sr, result: CheckerResult) -> None:
    enabled: list[str] = []
    for attr, (label, severity) in DEPRECATED_PROTOCOLS.items():
        if _accepted(sr, attr):
            enabled.append(label)
            result.findings.append(
                Finding(
                    f"ssl.protocol.{attr}",
                    f"Deprecated protocol enabled: {label}",
                    severity,
                    f"The server accepts {label}, which has known cryptographic weaknesses "
                    f"(e.g. POODLE, BEAST) and is deprecated (RFC 8996).",
                    f"Disable {label}; allow only TLS 1.2 and TLS 1.3.",
                    confidence=Confidence.VERIFIED,
                )
            )

    has_tls12 = bool(_accepted(sr, "tls_1_2_cipher_suites"))
    has_tls13 = bool(_accepted(sr, "tls_1_3_cipher_suites"))
    if has_tls12:
        enabled.append("TLS 1.2")
    if has_tls13:
        enabled.append("TLS 1.3")
    result.meta["enabled_protocols"] = enabled

    if not (has_tls12 or has_tls13):
        result.findings.append(
            Finding(
                "ssl.protocol.no_modern",
                "No modern TLS protocol",
                Severity.CRITICAL,
                "Neither TLS 1.2 nor TLS 1.3 is enabled.",
                "Enable TLS 1.2 and TLS 1.3.",
                evidence=f"enabled: {', '.join(enabled) or 'none'}",
                confidence=Confidence.VERIFIED,
            )
        )
    elif not has_tls13:
        result.findings.append(
            Finding(
                "ssl.protocol.no_tls_1_3",
                "TLS 1.3 not enabled",
                Severity.MEDIUM,
                "The server offers TLS 1.2 but not TLS 1.3. TLS 1.3 removes legacy cipher suites and "
                "renegotiation, and current baselines such as NIST SP 800-52r2 require server support for it.",
                "Enable TLS 1.3 on the server (OpenSSL 1.1.1+, nginx 1.13+, Apache 2.4.36+).",
                evidence=f"enabled: {', '.join(enabled)}",
                confidence=Confidence.VERIFIED,
            )
        )

    weak: list[str] = []
    for attr, label in WEAK_CIPHER_SCAN_ATTRS.items():
        for cs in _accepted(sr, attr):
            name = cs.cipher_suite.name
            if any(marker in name for marker in WEAK_CIPHER_MARKERS):
                weak.append(f"{label}: {name}")
    if weak:
        shown = ", ".join(weak[:5]) + ("..." if len(weak) > 5 else "")
        result.findings.append(
            Finding(
                "ssl.cipher.weak",
                "Weak cipher suites enabled",
                Severity.HIGH,
                f"The server accepts weak cipher suites: {shown}",
                "Disable RC4, 3DES, DES, NULL, EXPORT and anonymous cipher suites.",
                evidence="\n".join(weak[:10]),
                confidence=Confidence.VERIFIED,
            )
        )
