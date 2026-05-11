"""Config loader for vbeye.

Looks for `vbeye.toml` in:
  1. ./vbeye.toml (project-local)
  2. $VBEYE_CONFIG (env override)
  3. ~/.config/vbeye/config.toml (XDG-style)
  4. ~/.vbeye.toml (home fallback)

Falls back to safe defaults if nothing is found.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


@dataclass
class Branding:
    company_name: str = "Your Company Kft."
    author: str = "Security Auditor"
    email: str = "info@example.com"
    website: str = "https://example.com"
    logo_path: str = ""

    color_primary: str = "0B1E3F"   # navy
    color_accent: str = "00B4D8"    # cyan
    color_border: str = "C9A227"    # gold
    color_body: str = "2B2B2B"
    color_meta: str = "6B7280"
    color_critical: str = "B00020"


@dataclass
class Defaults:
    industry: str = "vállalat"
    compliance: str = "GDPR és NIS2"
    price_offer1: str = "100 000 – 180 000 Ft + ÁFA"
    duration_offer1: str = "2–4 munkanap"
    duration_offer2: str = "4–8 hét"
    price_offer2: str = "A végleges költség a jelenlegi rendszer állapotától és a szükséges beavatkozás mértékétől függ"
    scan_source: str = "securityheaders.com"


@dataclass
class Config:
    branding: Branding = field(default_factory=Branding)
    defaults: Defaults = field(default_factory=Defaults)
    source_path: str | None = None


def _candidate_paths() -> list[Path]:
    candidates = [Path.cwd() / "vbeye.toml"]
    env = os.environ.get("VBEYE_CONFIG")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.home() / ".config" / "vbeye" / "config.toml")
    candidates.append(Path.home() / ".vbeye.toml")
    return candidates


def load(explicit_path: str | None = None) -> Config:
    cfg = Config()
    path: Path | None = None
    if explicit_path:
        path = Path(explicit_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
    else:
        for p in _candidate_paths():
            if p.exists():
                path = p
                break

    if path is None:
        return cfg

    with path.open("rb") as f:
        data = tomllib.load(f)

    cfg.source_path = str(path)
    branding_data = data.get("branding", {})
    defaults_data = data.get("defaults", {})

    for k, v in branding_data.items():
        if hasattr(cfg.branding, k):
            setattr(cfg.branding, k, v)
    for k, v in defaults_data.items():
        if hasattr(cfg.defaults, k):
            setattr(cfg.defaults, k, v)

    return cfg


def to_dict(cfg: Config) -> dict:
    return {
        "branding": asdict(cfg.branding),
        "defaults": asdict(cfg.defaults),
        "source_path": cfg.source_path,
    }
