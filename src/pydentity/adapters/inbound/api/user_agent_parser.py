from __future__ import annotations

from dataclasses import dataclass

from ua_parser import parse


@dataclass(frozen=True, slots=True)
class ParsedUserAgent:
    device_name: str
    platform: str


_FALLBACK_PLATFORM = "Unknown"
_FALLBACK_DEVICE_NAME = "Unknown Device"


def parse_user_agent(raw: str | None) -> ParsedUserAgent:
    if not raw:
        return ParsedUserAgent(
            device_name=_FALLBACK_DEVICE_NAME,
            platform=_FALLBACK_PLATFORM,
        )

    try:
        result = parse(raw)
    except Exception:
        return ParsedUserAgent(
            device_name=_FALLBACK_DEVICE_NAME,
            platform=_FALLBACK_PLATFORM,
        )

    platform = (
        result.os.family if result.os and result.os.family else _FALLBACK_PLATFORM
    )

    browser = (
        result.user_agent.family
        if result.user_agent and result.user_agent.family
        else None
    )

    device_name = f"{browser} on {platform}" if browser else f"{platform} Device"

    return ParsedUserAgent(device_name=device_name, platform=platform)
