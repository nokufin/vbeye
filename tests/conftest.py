from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests
from urllib3._collections import HTTPHeaderDict

from vbeye.context import ScanContext
from vbeye.net import Page


def make_response(
    url: str = "https://example.com/",
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    set_cookies: list[str] | None = None,
    body: str = "<html><body></body></html>",
    history_urls: list[str] | None = None,
) -> requests.Response:
    raw_headers = HTTPHeaderDict()
    for k, v in (headers or {}).items():
        raw_headers.add(k, v)
    for c in set_cookies or []:
        raw_headers.add("Set-Cookie", c)

    resp = requests.Response()
    resp.url = url
    resp.status_code = status
    resp.headers = requests.structures.CaseInsensitiveDict(
        {k: ", ".join(raw_headers.getlist(k)) for k in raw_headers.keys()}
    )
    resp.raw = SimpleNamespace(headers=raw_headers)
    resp._content = body.encode("utf-8")
    resp.encoding = "utf-8"
    resp.history = []
    for h in history_urls or []:
        prev = requests.Response()
        prev.url = h
        prev.status_code = 301
        resp.history.append(prev)
    return resp


def make_ctx(
    url: str = "https://example.com/",
    *,
    response: requests.Response | None = None,
    error: str | None = None,
    timeout: int = 5,
) -> ScanContext:
    page = Page(requested_url=url, response=response, error=error)
    return ScanContext(url=url, timeout=timeout, page=page)


@pytest.fixture
def response_factory():
    return make_response


@pytest.fixture
def ctx_factory():
    return make_ctx
