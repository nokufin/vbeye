from __future__ import annotations

BOT_PROTECTION_DOMAINS = (
    "perfdrive.com",
    "datadome.co",
    "px-cdn.net",
    "px-cloud.net",
    "challenges.cloudflare.com",
    "incapsula.com",
    "imperva.com",
    "akamai-bm.com",
    "kasada.io",
    "shieldsquare.net",
    "f5.com/check",
)


def is_bot_protection_host(host: str) -> bool:
    h = (host or "").lower()
    return any(d in h for d in BOT_PROTECTION_DOMAINS)


def bot_protection_error_text(blocked_host: str) -> str:
    return (
        f"Blocked by bot management: the target redirected to {blocked_host}. "
        f"The response is a challenge page, not the target site, so results would be misleading. "
        f"Retry from another IP or with --user-agent, or have the target allowlist the scanner."
    )
