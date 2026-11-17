from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from vbeye.net import Page


@dataclass
class ScanContext:
    url: str
    timeout: int
    page: Page

    @property
    def host(self) -> str:
        return (urlparse(self.url).hostname or "").lower()
