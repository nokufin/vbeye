from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import sslyze
from conftest import make_ctx, make_response
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from vbeye.checkers import ssl as ssl_check
from vbeye.scoring import CheckerResult, Severity


def _ids(result: CheckerResult) -> set[str]:
    return {f.check_id for f in result.findings}


def _finding(result: CheckerResult, check_id: str):
    return next(f for f in result.findings if f.check_id == check_id)


def _name(value: str):
    return SimpleNamespace(rfc4514_string=lambda: value)


def _leaf(days_left: int = 200, key=None):
    key = key or ec.generate_private_key(ec.SECP256R1()).public_key()
    return SimpleNamespace(
        not_valid_after_utc=datetime.now(timezone.utc) + timedelta(days=days_left, hours=1),
        subject=_name("CN=example.com"),
        issuer=_name("CN=Test CA"),
        public_key=lambda: key,
    )


def _cert_attempt(leaf=None, trusted: bool = True, hostname_ok: bool = True):
    leaf = leaf or _leaf()
    dep = SimpleNamespace(
        received_certificate_chain=[leaf],
        verified_certificate_chain=[leaf] if trusted else None,
        leaf_certificate_subject_matches_hostname=hostname_ok,
    )
    return SimpleNamespace(result=SimpleNamespace(certificate_deployments=[dep]))


def _suites(*names: str):
    return SimpleNamespace(
        result=SimpleNamespace(
            accepted_cipher_suites=[SimpleNamespace(cipher_suite=SimpleNamespace(name=n)) for n in names]
        )
    )


EMPTY = SimpleNamespace(result=SimpleNamespace(accepted_cipher_suites=[]))
MODERN = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
TLS13 = "TLS_AES_128_GCM_SHA256"


def _scan_result(**overrides):
    attrs = {
        "certificate_info": _cert_attempt(),
        "ssl_2_0_cipher_suites": EMPTY,
        "ssl_3_0_cipher_suites": EMPTY,
        "tls_1_0_cipher_suites": EMPTY,
        "tls_1_1_cipher_suites": EMPTY,
        "tls_1_2_cipher_suites": _suites(MODERN),
        "tls_1_3_cipher_suites": _suites(TLS13),
    }
    attrs.update(overrides)
    return SimpleNamespace(**attrs)


def _completed(sr=None):
    return SimpleNamespace(
        scan_status=sslyze.ServerScanStatusEnum.COMPLETED,
        scan_result=sr or _scan_result(),
        connectivity_error_trace=None,
    )


def _no_connectivity(message: str = "Connection refused"):
    trace = SimpleNamespace(format_exception_only=lambda: [f"ConnectionToServerFailed: {message}\n"])
    return SimpleNamespace(
        scan_status=sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY,
        scan_result=None,
        connectivity_error_trace=trace,
    )


def _https_ctx(url: str = "https://example.com/"):
    return make_ctx(url, response=make_response(url))


class TestCertificate:
    def _eval(self, attempt) -> CheckerResult:
        result = CheckerResult(name="ssl", meta={"hostname": "example.com"})
        ssl_check._eval_certificate(SimpleNamespace(certificate_info=attempt), result)
        return result

    def test_valid_certificate_has_no_findings(self):
        result = self._eval(_cert_attempt())
        assert result.findings == []
        assert result.meta["cert_subject"] == "CN=example.com"
        assert result.meta["cert_key_type"] == "ECDSA (secp256r1)"

    @pytest.mark.parametrize(
        ("days", "check_id", "severity"),
        [
            (-3, "ssl.cert.expired", Severity.CRITICAL),
            (5, "ssl.cert.expiring", Severity.HIGH),
            (20, "ssl.cert.expiring_soon", Severity.MEDIUM),
        ],
    )
    def test_expiry_thresholds(self, days, check_id, severity):
        result = self._eval(_cert_attempt(_leaf(days_left=days)))
        assert _ids(result) == {check_id}
        assert _finding(result, check_id).severity == severity

    def test_untrusted_chain(self):
        assert "ssl.cert.untrusted" in _ids(self._eval(_cert_attempt(trusted=False)))

    def test_hostname_mismatch(self):
        result = self._eval(_cert_attempt(hostname_ok=False))
        assert "ssl.cert.hostname_mismatch" in _ids(result)
        assert "example.com" in _finding(result, "ssl.cert.hostname_mismatch").description

    def test_missing_certificate_info_is_ignored(self):
        assert self._eval(SimpleNamespace(result=None)).findings == []

    def test_legacy_not_valid_after(self):
        leaf = _leaf(days_left=-1)
        legacy = SimpleNamespace(
            not_valid_after=leaf.not_valid_after_utc.replace(tzinfo=None),
            subject=leaf.subject,
            issuer=leaf.issuer,
            public_key=leaf.public_key,
        )
        assert "ssl.cert.expired" in _ids(self._eval(_cert_attempt(legacy)))


class TestPublicKey:
    def _eval(self, key) -> CheckerResult:
        result = CheckerResult(name="ssl")
        ssl_check._eval_public_key(key, result)
        return result

    def test_weak_rsa(self):
        result = self._eval(rsa.generate_private_key(65537, 1024).public_key())
        assert _ids(result) == {"ssl.cert.weak_key"}
        assert result.meta["cert_key_size"] == 1024

    def test_strong_rsa(self):
        assert self._eval(rsa.generate_private_key(65537, 2048).public_key()).findings == []

    def test_ecdsa_p256_is_not_weak(self):
        assert self._eval(ec.generate_private_key(ec.SECP256R1()).public_key()).findings == []

    def test_weak_ecdsa_curve(self):
        result = self._eval(ec.generate_private_key(ec.SECP192R1()).public_key())
        assert _ids(result) == {"ssl.cert.weak_key"}

    def test_ed25519(self):
        result = self._eval(ed25519.Ed25519PrivateKey.generate().public_key())
        assert result.findings == []
        assert result.meta["cert_key_type"] == "Ed25519"


class TestProtocols:
    def _eval(self, **overrides) -> CheckerResult:
        result = CheckerResult(name="ssl")
        ssl_check._eval_protocols(_scan_result(**overrides), result)
        return result

    def test_modern_only(self):
        result = self._eval()
        assert result.findings == []
        assert result.meta["enabled_protocols"] == ["TLS 1.2", "TLS 1.3"]

    @pytest.mark.parametrize(
        ("attr", "severity"),
        [
            ("ssl_2_0_cipher_suites", Severity.CRITICAL),
            ("ssl_3_0_cipher_suites", Severity.HIGH),
            ("tls_1_0_cipher_suites", Severity.MEDIUM),
            ("tls_1_1_cipher_suites", Severity.MEDIUM),
        ],
    )
    def test_deprecated_protocols(self, attr, severity):
        result = self._eval(**{attr: _suites(MODERN)})
        finding = _finding(result, f"ssl.protocol.{attr}")
        assert finding.severity == severity

    def test_missing_tls13(self):
        result = self._eval(tls_1_3_cipher_suites=EMPTY)
        assert _ids(result) == {"ssl.protocol.no_tls_1_3"}

    def test_no_modern_protocol(self):
        result = self._eval(
            tls_1_0_cipher_suites=_suites(MODERN),
            tls_1_2_cipher_suites=EMPTY,
            tls_1_3_cipher_suites=EMPTY,
        )
        assert _finding(result, "ssl.protocol.no_modern").severity == Severity.CRITICAL

    def test_errored_scan_attempt_counts_as_not_enabled(self):
        result = self._eval(tls_1_3_cipher_suites=SimpleNamespace(result=None))
        assert "ssl.protocol.no_tls_1_3" in _ids(result)

    def test_weak_ciphers_on_any_legacy_protocol(self):
        result = self._eval(
            tls_1_0_cipher_suites=_suites("TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
            tls_1_2_cipher_suites=_suites(MODERN, "TLS_RSA_WITH_RC4_128_SHA"),
        )
        weak = _finding(result, "ssl.cipher.weak")
        assert "TLS 1.0: TLS_RSA_WITH_3DES_EDE_CBC_SHA" in weak.evidence
        assert "TLS 1.2: TLS_RSA_WITH_RC4_128_SHA" in weak.evidence


class TestRun:
    def test_clean_tls(self, monkeypatch):
        monkeypatch.setattr(ssl_check, "_scan", lambda host, port, timeout: _completed())
        result = ssl_check.run(_https_ctx())
        assert result.error is None
        assert _ids(result) == {"ssl.ok"}
        assert result.meta["hostname"] == "example.com"
        assert result.meta["port"] == 443

    def test_http_url_with_working_tls_is_scanned(self, monkeypatch):
        calls = []

        def fake_scan(host, port, timeout):
            calls.append((host, port))
            return _completed()

        monkeypatch.setattr(ssl_check, "_scan", fake_scan)
        ctx = make_ctx("http://example.com/", response=make_response("http://example.com/"))
        result = ssl_check.run(ctx)
        assert calls == [("example.com", 443)]
        assert "ssl.no_tls" not in _ids(result)

    def test_no_connectivity_on_plain_http_site_is_no_tls(self, monkeypatch):
        monkeypatch.setattr(ssl_check, "_scan", lambda host, port, timeout: _no_connectivity())
        ctx = make_ctx("http://example.com/", response=make_response("http://example.com/"))
        result = ssl_check.run(ctx)
        assert result.error is None
        finding = _finding(result, "ssl.no_tls")
        assert finding.severity == Severity.CRITICAL
        assert "example.com:443" in finding.evidence
        assert "Connection refused" in finding.evidence

    def test_no_connectivity_on_https_site_is_error(self, monkeypatch):
        monkeypatch.setattr(ssl_check, "_scan", lambda host, port, timeout: _no_connectivity())
        result = ssl_check.run(_https_ctx())
        assert result.findings == []
        assert "example.com:443" in result.error

    def test_no_connectivity_when_page_fetch_failed_is_error(self, monkeypatch):
        monkeypatch.setattr(ssl_check, "_scan", lambda host, port, timeout: _no_connectivity())
        result = ssl_check.run(make_ctx("http://example.com/", error="HTTP request failed: timeout"))
        assert result.findings == []
        assert result.error

    def test_scans_final_host_after_redirect(self, monkeypatch):
        calls = []

        def fake_scan(host, port, timeout):
            calls.append((host, port))
            return _completed()

        monkeypatch.setattr(ssl_check, "_scan", fake_scan)
        ctx = make_ctx("https://example.com/", response=make_response("https://www.example.com:8443/home"))
        result = ssl_check.run(ctx)
        assert calls == [("www.example.com", 8443)]
        assert result.meta["hostname"] == "www.example.com"

    def test_falls_back_to_requested_host_without_response(self, monkeypatch):
        calls = []
        monkeypatch.setattr(ssl_check, "_scan", lambda host, port, timeout: calls.append(host) or _completed())
        ssl_check.run(make_ctx("https://example.org/", error="HTTP request failed"))
        assert calls == ["example.org"]

    def test_unresolvable_hostname_is_error(self, monkeypatch):
        def fake_scan(host, port, timeout):
            raise sslyze.ServerHostnameCouldNotBeResolved("nope")

        monkeypatch.setattr(ssl_check, "_scan", fake_scan)
        result = ssl_check.run(_https_ctx())
        assert result.error.startswith("Hostname could not be resolved")

    def test_unexpected_exception_is_error(self, monkeypatch):
        def fake_scan(host, port, timeout):
            raise RuntimeError("boom")

        monkeypatch.setattr(ssl_check, "_scan", fake_scan)
        result = ssl_check.run(_https_ctx())
        assert result.error == "TLS scan failed: RuntimeError: boom"

    def test_timeout_is_passed_to_network_configuration(self, monkeypatch):
        captured = {}

        class FakeScanner:
            def queue_scans(self, requests):
                captured["requests"] = requests

            def get_results(self):
                yield _completed()

        def fake_request(server_location, network_configuration, scan_commands):
            captured["config"] = network_configuration
            captured["location"] = server_location
            return SimpleNamespace()

        monkeypatch.setattr(sslyze, "Scanner", FakeScanner)
        monkeypatch.setattr(sslyze, "ServerScanRequest", fake_request)
        monkeypatch.setattr(
            sslyze, "ServerNetworkLocation", lambda hostname, port: SimpleNamespace(hostname=hostname, port=port)
        )

        result = ssl_check.run(make_ctx("https://example.com/", response=make_response(), timeout=7))
        assert result.error is None
        config = captured["config"]
        assert config.network_timeout == 7
        assert config.network_max_retries == ssl_check.NETWORK_MAX_RETRIES
        assert config.tls_server_name_indication == "example.com"
        assert captured["location"].port == 443
