"""Provider and Indicator Allowlist Defense (Section 30 - SSRF Defense).

Enforces strict allowlists on external provider destinations and prevents
outbound queries to private, loopback, or cloud-metadata IP ranges.
"""

import ipaddress
import re
from typing import Set

from app.core.exceptions import AppValidationError

# Supported indicator types
ALLOWED_INDICATOR_TYPES: Set[str] = {"ip", "domain", "hash"}

# Approved external threat-intelligence providers
ALLOWED_PROVIDERS: Set[str] = {"virustotal", "abuseipdb"}

# Fixed approved HTTPS endpoints (cannot be overridden by user input)
APPROVED_BASE_URLS = {
    "virustotal": "https://www.virustotal.com/api/v3",
    "abuseipdb": "https://api.abuseipdb.com/api/v2",
}

# Domain name regex validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

# Hash regex (MD5, SHA1, SHA256)
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def validate_threat_intel_indicator(indicator: str, indicator_type: str = "ip") -> str:
    """Validate indicator and ensure it is not a private IP to defend against SSRF."""
    if not indicator or not isinstance(indicator, str):
        raise AppValidationError("Indicator value is required.")

    cleaned_val = indicator.strip()
    cleaned_type = indicator_type.strip().lower()

    if cleaned_type not in ALLOWED_INDICATOR_TYPES:
        raise AppValidationError(
            f"Unsupported indicator_type '{indicator_type}'. Allowed: {sorted(ALLOWED_INDICATOR_TYPES)}"
        )

    if cleaned_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(cleaned_val)
        except ValueError as exc:
            raise AppValidationError(f"Invalid IP indicator format: '{cleaned_val}'") from exc

        # SSRF Defense: reject private, loopback, link-local, multicast, reserved IPs
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        ):
            raise AppValidationError(
                f"Indicator IP '{cleaned_val}' is a private, loopback, or non-routable address. "
                f"External enrichment is prohibited for internal networks (SSRF defense)."
            )
        return str(ip_obj)

    elif cleaned_type == "domain":
        if not DOMAIN_REGEX.match(cleaned_val) or len(cleaned_val) > 253:
            raise AppValidationError(f"Invalid domain indicator format: '{cleaned_val}'")
        return cleaned_val.lower()

    elif cleaned_type == "hash":
        if not HASH_REGEX.match(cleaned_val):
            raise AppValidationError(f"Invalid cryptographic hash format: '{cleaned_val}'")
        return cleaned_val.lower()

    return cleaned_val


def validate_provider_name(provider: str) -> str:
    """Validate that the requested provider is in the approved allowlist."""
    cleaned = (provider or "").strip().lower()
    if cleaned not in ALLOWED_PROVIDERS:
        raise AppValidationError(
            f"Unsupported provider '{provider}'. Approved providers: {sorted(ALLOWED_PROVIDERS)}"
        )
    return cleaned
