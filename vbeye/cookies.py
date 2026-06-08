"""Shared cookie classification utilities used by multiple checkers."""
from __future__ import annotations

import re


SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "auth", "token", "jwt",
    "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "remember", "xsrf", "csrf",
)

# Many CMSes (Joomla, Drupal, CodeIgniter…) use a random hex hash as the
# session-cookie name. A 26-40 char hex string is overwhelmingly likely to
# be a session cookie even without an explicit keyword.
RANDOM_HASH_NAME_RE = re.compile(r"^[a-f0-9]{26,40}$", re.IGNORECASE)

# CSRF double-submit-cookie pattern names. These are INTENTIONALLY readable
# from JavaScript (the frontend reads them and sends as X-CSRF-Token header)
# — HttpOnly absence on these is by design, not a misconfiguration.
# Frameworks: Laravel (XSRF-TOKEN), Angular (XSRF-TOKEN), Django (csrftoken),
# Express csurf (_csrf), ASP.NET (__RequestVerificationToken), Rails (authenticity_token).
CSRF_TOKEN_NAME_RE = re.compile(
    r"^(xsrf[-_]?token|csrf[-_]?token|_csrf|x[-_]?csrf|csrftoken|"
    r"__requestverificationtoken|authenticity_token)$",
    re.IGNORECASE,
)


def is_likely_session_cookie(name: str) -> bool:
    n = name.lower()
    if any(hint in n for hint in SESSION_COOKIE_HINTS):
        return True
    if RANDOM_HASH_NAME_RE.match(n):
        return True
    return False


def is_csrf_token_cookie(name: str) -> bool:
    """True if the cookie name matches the CSRF double-submit token pattern.
    These cookies must be JS-readable, so a missing HttpOnly flag is by design
    and must NOT be reported as a session-flags issue."""
    return bool(CSRF_TOKEN_NAME_RE.match(name.strip()))


def iter_set_cookie_headers(resp) -> list[str]:
    """Return all Set-Cookie header values from a requests.Response.

    Folded `resp.headers.get('set-cookie')` only yields the joined string,
    which loses multi-cookie information. Use urllib3's getlist if available.
    """
    set_cookies = []
    if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
        set_cookies = resp.raw.headers.getlist("Set-Cookie")
    if not set_cookies:
        raw = resp.headers.get("set-cookie")
        if raw:
            set_cookies = [raw]
    return set_cookies
