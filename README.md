# vbeye

**Passive web security assessment from the command line.**

vbeye audits the externally visible security posture of a website: HTTP security headers, cookies, TLS configuration and the delivered page source. It produces a weighted score and an A-F grade, plus HTML and JSON reports. Every finding has a confidence level, so you can tell observed facts from heuristics.

vbeye is passive. It sends one HTTP GET and a set of TLS handshakes. It does no fuzzing, payload injection, brute forcing or crawling.

```
$ vbeye example.com
  ✓ headers (0.0s) - 7 findings
  ✓ ssl (4.3s) - 3 findings
  ✓ source (0.0s) - 0 findings

┌──────────────── vbeye · https://example.com ────────────────┐
│ Score: 6/100  Grade: F                                      │
│   high: 4    medium: 2    low: 2    info: 2                 │
└─────────────────────────────────────────────────────────────┘
                            HEADERS
│ HIGH   │ Strict-Transport-Security missing │ headers.hsts.missing │
│ HIGH   │ Content-Security-Policy missing   │ headers.csp.missing  │
│ HIGH   │ Clickjacking protection missing   │ headers.xfo.missing  │
...
```

## Features

- **Headers**: HSTS, CSP (including `frame-ancestors`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy. Also checks HTTP→HTTPS redirects, cross-host redirects, software version disclosure and end-of-life PHP.
- **Cookies**: parses `Set-Cookie` attributes, classifies session cookies and recognizes CSRF double-submit cookies.
- **TLS** (via [sslyze](https://github.com/nabla-c0d3/sslyze)): protocol support from SSLv2 to TLS 1.3, weak cipher suites, certificate trust, expiry, hostname match and key strength.
- **Source**: mixed content, missing Subresource Integrity, insecure forms, leaked secrets (with entropy and JWT-payload filtering), outdated JavaScript libraries matched by version and CVE, HTML comment leaks and CSRF token hints.
- **Bot-protection awareness**: if the target redirects to a bot-management or WAF challenge page (Cloudflare, DataDome, Imperva, Akamai, PerimeterX, Kasada and others), the scan aborts instead of reporting on the challenge page.
- **Batch mode**: scans many targets in parallel and writes a CSV summary.
- **CI-friendly**: JSON output and an exit code you can tune with `--fail-on`.
- **Extensible**: third-party output plugins load through Python entry points.

## Installation

Requires Python 3.10 or newer.

```bash
# Kali / Debian (recommended)
sudo apt install -y pipx
pipx install git+https://github.com/nokufin/vbeye.git

# From source
git clone https://github.com/nokufin/vbeye.git
cd vbeye
pipx install .
```

For development:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Usage

```
vbeye [options] TARGET
vbeye [options] --batch FILE
```

| Option | Description |
|---|---|
| `TARGET` | URL or hostname. `https://` is assumed when no scheme is given. |
| `--skip MODULE ...` | Skip one or more modules: `headers`, `ssl`, `source`. |
| `-t, --timeout SEC` | Network timeout in seconds (default 15). |
| `-A, --user-agent UA` | Custom User-Agent header. |
| `-o, --output FILE` | HTML report path for a single target. |
| `--output-dir DIR` | Directory for generated reports (default `./reports`). |
| `--json [FILE]` | Write JSON results. The path is optional. |
| `--no-html` | Do not write an HTML report. |
| `-q, --quiet` | Print only the result line and output paths. |
| `--no-color` | Disable colored output. |
| `--fail-on LEVEL` | Exit with code 1 if any finding is at or above `critical`, `high` (default), `medium` or `low`. Use `never` to always exit 0. |
| `-b, --batch FILE` | Scan every target in FILE: one per line, `#` starts a comment. |
| `-c, --concurrency N` | Number of parallel scans in batch mode, 1-16 (default 4). |
| `--csv FILE` | Path of the batch summary CSV. |
| `-V, --version` | Print the version. |

### Examples

```bash
vbeye example.com
vbeye https://example.com:8443/app --timeout 30
vbeye example.com --skip ssl --no-html --json result.json
vbeye example.com -q --fail-on medium            # CI gate
vbeye example.com -A "Mozilla/5.0 (X11; Linux x86_64)"
vbeye --batch targets.txt -c 8 --json            # parallel batch scan
```

### Output

| Format | Default location |
|---|---|
| HTML | `./reports/<host>_<timestamp>.html`. Self-contained, works offline. |
| JSON | `./reports/<host>_<timestamp>.json` when `--json` is given without a path. |
| Batch | `./reports/batch_<timestamp>/` holds one report per target and `summary.csv`. The CSV is sorted by grade, worst first. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No finding at or above the `--fail-on` threshold. |
| `1` | At least one finding at or above the threshold, in any target. |
| `2` | Usage error, unreadable targets file, output or plugin error, or a target that failed in batch mode. |
| `130` | Interrupted. |

## Checks

Check IDs are stable and appear in every output format.

### headers

| Check ID | Severity |
|---|---|
| `headers.no_https_redirect` | HIGH |
| `headers.redirect.cross_host` | MEDIUM |
| `headers.hsts.missing` / `.weak` / `.no_subdomains` | HIGH / MEDIUM / LOW |
| `headers.csp.missing` / `.weak` | HIGH / MEDIUM |
| `headers.xfo.missing` / `.frame_ancestors_permissive` / `.invalid` | HIGH / MEDIUM / LOW |
| `headers.xcto.missing` | LOW |
| `headers.referrer.missing` / `.weak` | LOW |
| `headers.permissions.missing` | INFO |
| `headers.tech.php_eol` | CRITICAL (≤ 8.0) / HIGH (8.1, 8.2) |
| `headers.disclosure.<header>` | LOW when a version is disclosed, INFO otherwise |
| `headers.cookie.session_flags` | CRITICAL when both Secure and HttpOnly are missing, HIGH when one is missing |
| `headers.cookie.flags` | LOW; MEDIUM for `SameSite=None` without `Secure` |
| `headers.cookie.csrf_flags` | LOW |
| `headers.response.non_2xx` | INFO. The page returned an error status, so results may describe an error page. |

HSTS is evaluated only when the final URL is HTTPS.

### ssl

| Check ID | Severity |
|---|---|
| `ssl.no_tls` | CRITICAL. No TLS on the host, and the site is served over plain HTTP. |
| `ssl.protocol.no_modern` | CRITICAL. Neither TLS 1.2 nor TLS 1.3 is enabled. |
| `ssl.protocol.ssl_2_0_cipher_suites` / `ssl_3_0_cipher_suites` | CRITICAL / HIGH |
| `ssl.protocol.tls_1_0_cipher_suites` / `tls_1_1_cipher_suites` | MEDIUM |
| `ssl.protocol.no_tls_1_3` | MEDIUM |
| `ssl.cipher.weak` | HIGH. Any RC4, 3DES, DES, NULL, EXPORT or anonymous suite is accepted. |
| `ssl.cert.expired` | CRITICAL |
| `ssl.cert.expiring` / `.expiring_soon` | HIGH (under 14 days) / MEDIUM (under 30 days) |
| `ssl.cert.untrusted` / `.hostname_mismatch` | HIGH |
| `ssl.cert.weak_key` / `.dsa_deprecated` | HIGH |

vbeye scans the host the site finally redirects to. The TLS scan runs even when the target is given as `http://`.

### source

| Check ID | Severity |
|---|---|
| `source.secret.exposed` | CRITICAL. Private keys, AWS, Slack, GitHub and Stripe secrets, and JWTs carrying server-side secret claims. |
| `source.form.password_on_http` | CRITICAL |
| `source.mixed_content` | HIGH |
| `source.form.http_action` | HIGH |
| `source.secret.jwt_hint` / `.google_api_key_hint` / `.generic_hint` | HIGH, requires manual validation |
| `source.sri.missing` | MEDIUM |
| `source.lib.outdated` | MEDIUM. jQuery < 3.5.0, Bootstrap < 3.4.1 or 4.0-4.3.0, AngularJS 1.x. |
| `source.mixed_content.protocol_relative` | LOW |
| `source.inline_handlers` / `source.comments.leak` / `source.tech.stale_analytics` | LOW |
| `source.csrf.hint` | LOW (INFO with `SameSite=Strict` session cookies) |
| `source.inline_scripts` / `source.form.autocomplete_off` | INFO |

## Confidence levels

| Level | Meaning |
|---|---|
| `VERIFIED` | Directly observed in the server response, e.g. a missing header, an expired certificate or an HTTP form action. |
| `STRONG INDICATOR` | Strong signal that additional context could refine, e.g. a missing SRI attribute or a library version taken from a URL. |
| `MANUAL VALIDATION REQUIRED` | Heuristic that needs manual confirmation, e.g. a generic secret pattern, a suspicious comment or a CSRF hint. |

## Scoring

Each scan starts at 100. Every finding deducts points by severity:

| Severity | Penalty |
|---|---|
| CRITICAL | 35 |
| HIGH | 18 |
| MEDIUM | 8 |
| LOW | 3 |
| INFO / OK | 0 |
| Module error (timeout, connection failure, bot block) | 5 per module |

The penalty is adjusted by these rules:

- **Category ceiling**: one module can deduct at most 45 (headers), 35 (source) or 50 (ssl) points, and any other module at most 30. This keeps a pile of hardening gaps in one area from dominating the score.
- **Real-risk findings** always deduct their full weight, even above the ceiling: `ssl.no_tls`, `ssl.cert.expired`, `ssl.protocol.no_modern`, `ssl.protocol.ssl_2_0_cipher_suites`, `source.form.password_on_http`, `source.mixed_content`, `source.secret.exposed`, `headers.tech.php_eol` and `headers.cookie.session_flags`.
- **Systemic failure**: three or more HIGH findings in one module lift that module's ceiling.
- **E floor**: without a real-risk finding and with fewer than three HIGH findings overall, the score never drops below 30 (grade E). F is reserved for real exposure.

| Score | 90+ | 80-89 | 65-79 | 50-64 | 30-49 | < 30 |
|---|---|---|---|---|---|---|
| Grade | A | B | C | D | E | F |

## Plugins

Output plugins register under the `vbeye.plugins` entry-point group. A plugin is a class with:

```python
class MyPlugin:
    name = "myformat"

    def add_arguments(self, parser): ...          # add CLI flags
    def enabled(self, args) -> bool: ...          # is the plugin requested?
    def prepare(self, args) -> None: ...          # validate once; raise vbeye.plugins.PluginError
    def write(self, report, args, output_dir, stem): ...  # return the written Path
```

```toml
[project.entry-points."vbeye.plugins"]
myformat = "my_package.plugin:MyPlugin"
```

`report` is a `vbeye.engine.ScanReport` and provides `target`, `results`, `score`, `grade` and `to_dict()`. In batch mode `write` may run in several threads at once.

## Adding a check module

1. Create `vbeye/checkers/<name>.py` with a `run(ctx: ScanContext) -> CheckerResult` function. `ctx.page` holds the already fetched response, so do not send another request for the same page.
2. Register the function in `CHECKERS` in `vbeye/engine.py`.
3. Optionally, set a ceiling in `CATEGORY_CEILING` and list real-risk check IDs in `REAL_RISK_CHECK_IDS` (`vbeye/scoring.py`).
4. Add tests under `tests/`. Use the `make_response` and `make_ctx` helpers in `tests/conftest.py`; tests must not use the network.

## Legal

Use vbeye only against systems you own, or that you have written permission to assess (penetration-test scope, bug bounty program, client engagement). The authors accept no liability for misuse.

## License

[MIT](LICENSE)
