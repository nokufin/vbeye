from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from vbeye import __version__
from vbeye.bot_protection import bot_protection_error_text, is_bot_protection_host

DEFAULT_USER_AGENT = f"vbeye/{__version__} (+https://github.com/nokufin/vbeye)"

BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass
class Page:
    requested_url: str
    response: requests.Response | None = None
    error: str | None = None
    blocked_by: str | None = None
    meta: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.response is not None and self.error is None

    @property
    def final_url(self) -> str:
        return self.response.url if self.response is not None else self.requested_url

    @property
    def final_host(self) -> str:
        return (urlparse(self.final_url).hostname or "").lower()

    @property
    def is_https(self) -> bool:
        return self.final_url.startswith("https://")

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response is not None else None


def fetch(url: str, timeout: int, user_agent: str | None = None) -> Page:
    headers = dict(BASE_HEADERS)
    headers["User-Agent"] = user_agent or DEFAULT_USER_AGENT
    page = Page(requested_url=url)
    try:
        page.response = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
    except requests.RequestException as e:
        page.error = f"HTTP request failed: {e}"
        return page

    if is_bot_protection_host(page.final_host):
        page.blocked_by = page.final_host
        page.error = bot_protection_error_text(page.final_host)
    return page
