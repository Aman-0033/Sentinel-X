"""Telemetry Ingestion Pipeline and Quarantine Service.

Strictly enforces Section 30, Section 31, and Section 32 of architecture.md:
- Batch flow ingestion and multi-format (CSV/JSON) upload processing.
- Size limits, type inspection, quarantine isolation, and CSV injection sanitization.
"""

import csv
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.core.exceptions import AppValidationError
from app.core.validation import (
    validate_ip_address,
    validate_port,
    validate_protocol,
)
from app.db.models.network_flow import NetworkFlow
from app.repositories.flows import NetworkFlowRepository

logger = logging.getLogger("sentinel.ingestion")

MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit
MAX_BATCH_FLOW_COUNT = 1000  # Max flows per batch request
DEFAULT_QUARANTINE_DIR = Path("tmp/quarantine")

CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> Any:
    """Neutralize CSV formula injection attacks (DDE/formula execution)."""
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.startswith(CSV_FORMULA_PREFIXES):
            return f"'{cleaned}"
        return cleaned
    return value


class IngestionService:
    """Service orchestrating ingestion validation, file quarantine, and persistence."""

    def __init__(self, db: Session, quarantine_dir: Optional[Path] = None) -> None:
        self.db = db
        self.repo = NetworkFlowRepository(db)
        self.quarantine_dir = quarantine_dir or DEFAULT_QUARANTINE_DIR
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def validate_and_normalize_flow(self, raw_flow: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize a single raw network flow record."""
        # 1. Timestamp
        raw_ts = raw_flow.get("timestamp")
        if not raw_ts:
            timestamp = datetime.now(timezone.utc)
        elif isinstance(raw_ts, datetime):
            timestamp = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        else:
            try:
                dt = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                timestamp = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception as exc:
                raise AppValidationError(f"Invalid timestamp format: '{raw_ts}'") from exc

        # 2. IP Addresses
        source_ip = validate_ip_address(raw_flow.get("source_ip", ""))
        destination_ip = validate_ip_address(raw_flow.get("destination_ip", ""))

        # 3. Ports
        source_port = None
        if (
            raw_flow.get("source_port") is not None
            and str(raw_flow.get("source_port")).strip() != ""
        ):
            source_port = validate_port(raw_flow["source_port"], "source_port")

        dest_port = None
        if (
            raw_flow.get("destination_port") is not None
            and str(raw_flow.get("destination_port")).strip() != ""
        ):
            dest_port = validate_port(raw_flow["destination_port"], "destination_port")

        # 4. Protocol
        protocol = None
        if raw_flow.get("protocol"):
            protocol = validate_protocol(raw_flow["protocol"])

        # 5. Packets and Bytes
        packets = None
        if raw_flow.get("packets") is not None and str(raw_flow.get("packets")).strip() != "":
            try:
                packets = int(raw_flow["packets"])
                if packets < 0:
                    raise ValueError()
            except (ValueError, TypeError) as exc:
                raise AppValidationError("packets must be a non-negative integer.") from exc

        byte_count = None
        if raw_flow.get("bytes") is not None and str(raw_flow.get("bytes")).strip() != "":
            try:
                byte_count = int(raw_flow["bytes"])
                if byte_count < 0:
                    raise ValueError()
            except (ValueError, TypeError) as exc:
                raise AppValidationError("bytes must be a non-negative integer.") from exc

        # 6. Duration
        duration_ms = None
        if (
            raw_flow.get("duration_ms") is not None
            and str(raw_flow.get("duration_ms")).strip() != ""
        ):
            try:
                duration_ms = Decimal(str(raw_flow["duration_ms"]))
                if duration_ms < 0:
                    raise ValueError()
            except (ValueError, TypeError) as exc:
                raise AppValidationError("duration_ms must be a non-negative number.") from exc

        direction = raw_flow.get("direction")
        if direction:
            direction = str(direction).strip().upper()[:20]

        return {
            "source_id": raw_flow.get("source_id"),
            "timestamp": timestamp,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": dest_port,
            "protocol": protocol,
            "packets": packets,
            "bytes": byte_count,
            "duration_ms": duration_ms,
            "direction": direction,
            "raw_features": raw_flow.get("raw_features", {}),
        }

    def ingest_flow_batch(
        self,
        flows: List[Dict[str, Any]],
        source_id: Optional[str] = None,
    ) -> List[NetworkFlow]:
        """Ingest a batch of in-memory network flow dictionaries."""
        if not flows or not isinstance(flows, list):
            raise AppValidationError("Flow batch must be a non-empty array of records.")

        if len(flows) > MAX_BATCH_FLOW_COUNT:
            raise AppValidationError(
                f"Batch exceeds maximum limit of {MAX_BATCH_FLOW_COUNT} flows per request."
            )

        normalized_batch = []
        for index, item in enumerate(flows):
            if not isinstance(item, dict):
                raise AppValidationError(f"Batch item at index {index} must be an object.")
            if source_id and not item.get("source_id"):
                item["source_id"] = source_id
            normalized = self.validate_and_normalize_flow(item)
            normalized_batch.append(normalized)

        return self.repo.create_batch(normalized_batch)

    def process_quarantined_upload(
        self,
        file_bytes: bytes,
        file_extension: str,
        source_id: Optional[str] = None,
    ) -> Tuple[int, List[NetworkFlow]]:
        """Quarantine uploaded telemetry file, validate content, and process records.

        Strictly follows Section 32 upload pipeline.
        """
        if not file_bytes:
            raise AppValidationError("Uploaded file is empty.")

        # 1. Size Check
        if len(file_bytes) > MAX_UPLOAD_SIZE_BYTES:
            raise AppValidationError(
                f"Uploaded file exceeds maximum limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
            )

        # 2. Type Check
        clean_ext = file_extension.lower().strip().lstrip(".")
        if clean_ext not in ("csv", "json"):
            raise AppValidationError(
                f"Unsupported file format '.{clean_ext}'. Only CSV and JSON are allowed."
            )

        # 3. Discard client filename, assign UUID quarantine filename
        quarantine_filename = f"{uuid.uuid4().hex}.{clean_ext}"
        quarantine_path = self.quarantine_dir / quarantine_filename

        try:
            # 4. Save to quarantine
            with open(quarantine_path, "wb") as f:
                f.write(file_bytes)

            # 5. Parse and process
            flows: List[Dict[str, Any]] = []
            if clean_ext == "csv":
                flows = self._parse_quarantined_csv(quarantine_path, source_id)
            elif clean_ext == "json":
                flows = self._parse_quarantined_json(quarantine_path, source_id)

            persisted = self.ingest_flow_batch(flows, source_id=source_id)
            return len(persisted), persisted

        finally:
            # 6. Cleanup quarantine file after processing
            if quarantine_path.exists():
                try:
                    os.remove(quarantine_path)
                except Exception:
                    pass

    def _parse_quarantined_csv(
        self, file_path: Path, source_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        flows = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise AppValidationError("CSV file missing header row.")

            # Sanitize headers and rows against CSV injection
            for row in reader:
                cleaned_row = {k.strip(): sanitize_csv_cell(v) for k, v in row.items() if k}
                flows.append(cleaned_row)

        return flows

    def _parse_quarantined_json(
        self, file_path: Path, source_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        with open(file_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except Exception as exc:
                raise AppValidationError(f"Malformed JSON in uploaded file: {str(exc)}") from exc

        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "flows" in data and isinstance(data["flows"], list):
            return data["flows"]
        else:
            raise AppValidationError(
                "JSON upload must be an array of flow objects or contain a 'flows' array."
            )
