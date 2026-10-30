"""Feature engineering for network flow analysis.

Extracts statistical, protocol, and directional telemetry features
from raw network flow records for classifier and anomaly detection models.
"""

from decimal import Decimal
from typing import Any, Dict, List

import numpy as np

# Canonical feature list expected by model artifacts
FEATURE_NAMES: List[str] = [
    "packet_count",
    "byte_count",
    "duration_ms",
    "bytes_per_packet",
    "bytes_per_second",
    "packets_per_second",
    "is_well_known_port",
    "is_ephemeral_port",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "failed_connection_ratio",
    "request_frequency",
    "direction_inbound",
    "direction_outbound",
]

# Standard attack labels supported by SENTINEL-X
ATTACK_CLASSES: List[str] = [
    "Benign",
    "Port Scan",
    "Brute Force",
    "DDoS",
    "Malware C2",
    "Data Exfiltration",
]


def extract_flow_features(flow_dict: Dict[str, Any]) -> Dict[str, float]:
    """Extract standard numeric features from a single flow record.

    Handles type conversions, null values, and derived rates safely.
    """
    # 1. Base counts
    raw_packets = flow_dict.get("packets")
    packet_count = float(raw_packets) if raw_packets is not None else 1.0

    raw_bytes = flow_dict.get("bytes")
    byte_count = float(raw_bytes) if raw_bytes is not None else 0.0

    raw_duration = flow_dict.get("duration_ms")
    if isinstance(raw_duration, (int, float, Decimal)):
        duration_ms = float(raw_duration)
    else:
        duration_ms = 0.0

    # 2. Derived traffic ratios
    bytes_per_packet = byte_count / max(packet_count, 1.0)
    duration_sec = (duration_ms / 1000.0) + 0.001  # Epsilon prevents zero-division
    bytes_per_second = byte_count / duration_sec
    packets_per_second = packet_count / duration_sec

    # 3. Port characteristics
    dest_port = flow_dict.get("destination_port")
    try:
        dest_port_num = int(dest_port) if dest_port is not None else 0
    except (ValueError, TypeError):
        dest_port_num = 0

    is_well_known_port = 1.0 if (1 <= dest_port_num < 1024) else 0.0
    is_ephemeral_port = 1.0 if (dest_port_num >= 49152) else 0.0

    # 4. Protocol one-hot encoding
    raw_proto = str(flow_dict.get("protocol") or "").strip().upper()
    protocol_tcp = 1.0 if raw_proto == "TCP" else 0.0
    protocol_udp = 1.0 if raw_proto == "UDP" else 0.0
    protocol_icmp = 1.0 if raw_proto == "ICMP" else 0.0

    # 5. Behavioral indicators
    raw_failed = flow_dict.get("failed_connection_ratio", 0.0)
    try:
        failed_connection_ratio = float(raw_failed) if raw_failed is not None else 0.0
    except (ValueError, TypeError):
        failed_connection_ratio = 0.0

    raw_freq = flow_dict.get("request_frequency", 0.0)
    try:
        request_frequency = float(raw_freq) if raw_freq is not None else 0.0
    except (ValueError, TypeError):
        request_frequency = 0.0

    # 6. Direction one-hot
    direction = str(flow_dict.get("direction") or "").strip().upper()
    direction_inbound = 1.0 if direction == "INBOUND" else 0.0
    direction_outbound = 1.0 if direction == "OUTBOUND" else 0.0

    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_ms": duration_ms,
        "bytes_per_packet": bytes_per_packet,
        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,
        "is_well_known_port": is_well_known_port,
        "is_ephemeral_port": is_ephemeral_port,
        "protocol_tcp": protocol_tcp,
        "protocol_udp": protocol_udp,
        "protocol_icmp": protocol_icmp,
        "failed_connection_ratio": failed_connection_ratio,
        "request_frequency": request_frequency,
        "direction_inbound": direction_inbound,
        "direction_outbound": direction_outbound,
    }


def flow_features_to_vector(features: Dict[str, float]) -> np.ndarray:
    """Convert extracted features dictionary to a canonical numpy 1D vector."""
    return np.array([features[name] for name in FEATURE_NAMES], dtype=np.float32)
