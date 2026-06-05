"""Shared cookie classification utilities used by multiple checkers."""
from __future__ import annotations


SESSION_COOKIE_HINTS = (
    "session", "sess", "sid", "auth", "token", "jwt",
    "phpsessid", "jsessionid", "asp.net_sessionid",
    "connect.sid", "remember", "xsrf", "csrf",
)


def is_likely_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(hint in n for hint in SESSION_COOKIE_HINTS)


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
