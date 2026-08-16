"""Human-readable and machine-readable audit reporting."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .comparison import Drift
from .exceptions import ValidationError
from .storage import atomic_write_json
from .validation import validate_json_path


def drift_to_dict(item: Drift) -> dict[str, Any]:
    name, record_type, set_identifier = item.identity
    result: dict[str, Any] = {
        "kind": item.kind.value,
        "name": name,
        "type": record_type,
        "dangling_dns_candidate": item.dangling_candidate,
    }
    if set_identifier:
        result["set_identifier"] = set_identifier
    if item.baseline is not None:
        result["baseline"] = item.baseline.to_dict()
    if item.current is not None:
        result["current"] = item.current.to_dict()
    return result


def render_text(drift: tuple[Drift, ...]) -> str:
    if not drift:
        return "Audit complete: no DNS baseline drift detected."
    lines = [f"Audit complete: {len(drift)} DNS baseline deviation(s) detected."]
    for item in drift:
        name, record_type, set_identifier = item.identity
        identifier = f" [{set_identifier}]" if set_identifier else ""
        candidate = (
            " (dangling-DNS candidate; verification required)"
            if item.dangling_candidate
            else ""
        )
        lines.append(f"- {item.kind.value.upper()}: {name} {record_type}{identifier}{candidate}")
    return "\n".join(lines)


def write_json_report(path_value: str | Path, drift: tuple[Drift, ...]) -> Path:
    try:
        path = validate_json_path(path_value, for_write=True)
        atomic_write_json(
            path,
            {"drift_count": len(drift), "drift": [drift_to_dict(item) for item in drift]},
        )
    except (OSError, ValidationError) as exc:
        raise ValidationError(f"cannot write report: {exc}") from exc
    return path
