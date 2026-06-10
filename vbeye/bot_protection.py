"""Bot-management / WAF challenge detection.

Shared by checkers that follow HTTP redirects (headers, source). If a target's
cross-host redirect lands on a known bot-management challenge service, the scan
no longer measures the original site — it measures the challenge page. The
checker should abort with a clear error instead of emitting misleading findings.
"""
from __future__ import annotations


# Domain fragments belonging to bot-management / WAF challenge services.
BOT_PROTECTION_DOMAINS = (
    "perfdrive.com",                # Radware Bot Manager
    "datadome.co",                  # DataDome
    "px-cdn.net",                   # PerimeterX / HUMAN
    "px-cloud.net",
    "challenges.cloudflare.com",    # Cloudflare Turnstile / managed challenge
    "incapsula.com",                # Imperva Cloud WAF
    "imperva.com",
    "akamai-bm.com",                # Akamai Bot Manager
    "kasada.io",                    # Kasada
    "shieldsquare.net",             # ShieldSquare
    "f5.com/check",                 # F5 BIG-IP challenge
)


def is_bot_protection_host(host: str) -> bool:
    h = (host or "").lower()
    return any(d in h for d in BOT_PROTECTION_DOMAINS)


def bot_protection_error_text(blocked_host: str) -> str:
    return (
        f"Bot-management blokk: a target átirányított ide: {blocked_host}. "
        f"A scan nem mérhető — a védő szolgáltatás challenge-oldalt szolgált fel "
        f"a vbeye User-Agent-re. Másik IP / User-Agent szükséges, vagy a "
        f"céloldalt audit-célból white-list-eltetni."
    )
