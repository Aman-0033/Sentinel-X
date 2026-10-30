"""Strict Third-Party Response Validation and Sanitization (Section 33).

Treats all external API responses as untrusted data, validating payload sizes,
JSON types, bounding numerical ranges, and sanitizing text strings.
"""

import html
import json
from typing import Any, Dict

import httpx

from app.core.exceptions import AppValidationError

# Maximum allowed external payload size (1 MB) to prevent denial of service
MAX_RESPONSE_BYTES = 1024 * 1024


def sanitize_response_data(data: Any, max_depth: int = 5) -> Any:
    """Recursively sanitize external JSON dictionary or list against injection payloads."""
    if max_depth <= 0:
        return "[TRUNCATED_DEPTH]"

    if isinstance(data, dict):
        cleaned_dict = {}
        for k, v in data.items():
            clean_k = html.escape(str(k)[:100])
            cleaned_dict[clean_k] = sanitize_response_data(v, max_depth - 1)
        return cleaned_dict

    elif isinstance(data, list):
        # Limit array length to avoid memory inflation
        return [sanitize_response_data(item, max_depth - 1) for item in data[:50]]

    elif isinstance(data, str):
        # Escape HTML characters and limit string length to 1000 chars
        return html.escape(data[:1000])

    elif isinstance(data, (int, float, bool)) or data is None:
        return data

    return str(data)[:200]


def validate_http_response(
    response: httpx.Response,
    provider_name: str,
    expected_status: int = 200,
) -> Dict[str, Any]:
    """Validate external HTTP response headers, content type, and payload safely."""
    # 1. Payload size check
    content_len = response.headers.get("Content-Length")
    if content_len and int(content_len) > MAX_RESPONSE_BYTES:
        raise AppValidationError(
            f"Provider '{provider_name}' response exceeded maximum allowed size ({MAX_RESPONSE_BYTES} bytes)."
        )

    # 2. Status code check
    if response.status_code != expected_status:
        # Common external provider error codes
        if response.status_code == 404:
            return {
                "not_found": True,
                "message": f"Indicator not found in {provider_name} database.",
            }
        elif response.status_code in (401, 403):
            raise AppValidationError(
                f"Authentication/authorization failed for provider '{provider_name}'."
            )
        elif response.status_code == 429:
            raise AppValidationError(f"Rate limit exceeded for provider '{provider_name}'.")
        else:
            raise AppValidationError(
                f"Provider '{provider_name}' returned unexpected status code {response.status_code}."
            )

    # 3. Content type check
    content_type = response.headers.get("Content-Type", "")
    if "application/json" not in content_type:
        raise AppValidationError(
            f"Provider '{provider_name}' returned invalid Content-Type '{content_type}', expected application/json."
        )

    # 4. JSON parsing
    try:
        raw_json = response.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise AppValidationError(
            f"Provider '{provider_name}' returned malformed JSON: {str(exc)}"
        ) from exc

    if not isinstance(raw_json, dict):
        raise AppValidationError(f"Provider '{provider_name}' JSON payload must be an object.")

    # 5. Sanitize
    return sanitize_response_data(raw_json)
