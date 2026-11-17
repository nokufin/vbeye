# Changelog

## 1.1.0

### Added
- Scan engine that sends a single HTTP request and shares the response with all modules.
- `--fail-on`, `--quiet`, `--no-color`, `--user-agent` and `--output-dir` options.
- `--json` writes per-target JSON in batch mode.
- Output plugin interface (`vbeye.plugins` entry-point group).
- `headers.response.non_2xx`: flags scans of error pages.
- Subresource Integrity checks for external stylesheets.
- Test suite and CI.

### Changed
- All output is in English.
- Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` error. Single and batch modes now behave the same.
- The TLS scan runs against the host the site finally redirects to, and honors `--timeout`.
- Session cookie severity: CRITICAL when both Secure and HttpOnly are missing, HIGH when one is missing. A missing SameSite on its own is LOW.
- `ssl.protocol.no_tls_1_3` is now MEDIUM.
- Outdated libraries are detected by comparing versions.
- Form findings are reported once per page.
- The DOCX deliverable has been removed from the core package.

### Fixed
- The ssl module failed to import on Python 3.12 and newer, because sslyze 5 relies on the removed `ssl.match_hostname`. vbeye now requires sslyze 6.
- `ssl.no_tls` was reported for any `http://` target, even if the host served valid TLS.
- `<link rel="canonical|alternate|preconnect">` with an `http://` URL was reported as mixed content.
- Protocol-relative URLs were treated as a real-risk HIGH finding.
- Cookie flags were detected by substring, so a cookie name or value containing "secure" could hide a missing flag.
- Session-cookie detection matched substrings such as `author` or `inside`.
- Bootstrap 3.4.1 was reported as vulnerable to CVE-2019-8331.
- An unexpected error in one module aborted the whole single-target scan.

## 1.0.0

- Initial release: headers, ssl and source modules, HTML and JSON reports, batch mode.
