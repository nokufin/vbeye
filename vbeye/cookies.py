from __future__ import annotations

import re

SESSION_HINT_TOKENS = frozenset({
    "session", "sessid", "sessionid", "sess", "sid", "auth", "token", "jwt",
    "login", "logged", "remember", "identity",
})

SESSION_EXACT_NAMES = frozenset({
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid", "connect.sid",
    "laravel_session", "ci_session", "cfid", "cftoken", "sails.sid", "rack.session",
    "_session_id", "express.sid", "koa.sess", "django_session",
    ".aspnetcore.session", ".aspxauth", ".aspnetcore.cookies",
})

# Joomla, Drupal and others name session cookies with a random hex digest.
RANDOM_HASH_NAME_RE = re.compile(r"^(?:sess_|ssess|sess)?[a-f0-9]{26,64}$", re.IGNORECASE)

# Double-submit CSRF cookies must be readable by JavaScript, so HttpOnly is absent by design.
CSRF_TOKEN_NAME_RE = re.compile(
    r"^(xsrf[-_]?token|csrf[-_]?token|_csrf|x[-_]?csrf|csrftoken|"
    r"__requestverificationtoken|authenticity_token)$",
    re.IGNORECASE,
)

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")


def parse_set_cookie(header: str) -> tuple[str, str, dict[str, str | None]]:
    parts = header.split(";")
    first = parts[0]
    if "=" in first:
        name, value = first.split("=", 1)
    else:
        name, value = first, ""
    attrs: dict[str, str | None] = {}
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.lower()] = None
    return name.strip(), value.strip(), attrs


def _name_tokens(name: str) -> list[str]:
    tokens: list[str] = []
    for chunk in _SPLIT_RE.split(name):
        if not chunk:
            continue
        tokens.extend(t.lower() for t in _CAMEL_RE.split(chunk) if t)
    return tokens


def is_csrf_token_cookie(name: str) -> bool:
    return bool(CSRF_TOKEN_NAME_RE.match(name.strip()))


def is_likely_session_cookie(name: str) -> bool:
    n = name.strip().lower()
    if not n:
        return False
    if n in SESSION_EXACT_NAMES:
        return True
    if n.startswith(("wordpress_logged_in", "wordpress_sec", "aspsessionid")):
        return True
    if RANDOM_HASH_NAME_RE.match(n):
        return True
    return any(t in SESSION_HINT_TOKENS for t in _name_tokens(name))


def iter_set_cookie_headers(resp) -> list[str]:
    set_cookies: list[str] = []
    raw = getattr(resp, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        set_cookies = list(raw_headers.getlist("Set-Cookie"))
    if not set_cookies:
        folded = resp.headers.get("set-cookie")
        if folded:
            set_cookies = [folded]
    return set_cookies
