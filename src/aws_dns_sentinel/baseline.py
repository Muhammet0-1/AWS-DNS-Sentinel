"""Versioned, validated, and atomic baseline persistence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .exceptions import BaselineError, ValidationError
from .models import DNSRecord
from .storage import atomic_write_json
from .validation import validate_hosted_zone_id, validate_json_path

SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Baseline:
    hosted_zone_id: str | None
    records: tuple[DNSRecord, ...]
    created_at: str | None = None


def load_baseline(path_value: str | Path, expected_zone_id: str | None = None) -> Baseline:
    """Load the current schema or the original list-only baseline format."""
    try:
        path = validate_json_path(path_value, must_exist=True)
        with path.open(encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise BaselineError(f"cannot load baseline: {exc}") from exc

    try:
        if isinstance(payload, list):
            records = tuple(DNSRecord.from_legacy_dict(item) for item in payload)
            baseline = Baseline(hosted_zone_id=None, records=records)
        elif isinstance(payload, dict):
            allowed = {"schema_version", "created_at", "hosted_zone_id", "records"}
            if set(payload) - allowed:
                raise BaselineError("baseline contains unsupported top-level fields")
            if payload.get("schema_version") != SCHEMA_VERSION:
                raise BaselineError("unsupported baseline schema version")
            zone_id = validate_hosted_zone_id(payload["hosted_zone_id"])
            raw_records = payload["records"]
            if not isinstance(raw_records, list):
                raise BaselineError("baseline records must be a list")
            records = tuple(DNSRecord.from_dict(item) for item in raw_records)
            created_at = payload.get("created_at")
            if not isinstance(created_at, str):
                raise BaselineError("baseline created_at must be an ISO-8601 string")
            datetime.fromisoformat(created_at)
            baseline = Baseline(zone_id, records, created_at)
        else:
            raise BaselineError("baseline root must be an object or legacy list")
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise BaselineError(f"invalid baseline data: {exc}") from exc

    identities = [record.identity for record in baseline.records]
    if len(identities) != len(set(identities)):
        raise BaselineError("baseline contains duplicate record identities")
    if expected_zone_id and baseline.hosted_zone_id:
        normalized_expected = validate_hosted_zone_id(expected_zone_id)
        if baseline.hosted_zone_id != normalized_expected:
            raise BaselineError("baseline belongs to a different hosted zone")
    return baseline


def save_baseline(
    path_value: str | Path,
    zone_id: str,
    records: tuple[DNSRecord, ...],
    *,
    overwrite: bool = False,
) -> Path:
    """Atomically write a private baseline JSON file."""
    try:
        path = validate_json_path(path_value, for_write=True)
        normalized_zone_id = validate_hosted_zone_id(zone_id)
    except ValidationError as exc:
        raise BaselineError(str(exc)) from exc
    if path.exists() and not overwrite:
        raise BaselineError(f"baseline already exists: {path}; use --overwrite to replace it")

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hosted_zone_id": normalized_zone_id,
        "records": [record.to_dict() for record in sorted(records, key=lambda item: item.identity)],
    }
    try:
        atomic_write_json(path, payload)
    except OSError as exc:
        raise BaselineError(f"cannot write baseline: {exc}") from exc
    return path
