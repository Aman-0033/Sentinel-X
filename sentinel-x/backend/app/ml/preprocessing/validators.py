"""Validation functions for ML input telemetry."""

from typing import Any, Dict

from app.core.exceptions import AppValidationError


def validate_flow_for_ml(flow: Dict[str, Any]) -> None:
    """Validate that raw flow dictionary has necessary fields for ML processing."""
    if not isinstance(flow, dict):
        raise AppValidationError("Flow input must be a dictionary.")

    # Must have either source_ip or destination_ip
    if not flow.get("source_ip") and not flow.get("destination_ip"):
        raise AppValidationError("Flow must contain at least source_ip or destination_ip.")
