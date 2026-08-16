"""Pure DNS baseline comparison logic with no AWS or network dependency."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from .exceptions import ValidationError
from .models import DNSRecord


class DriftKind(str, Enum):
    MISSING = "missing"
    MODIFIED = "modified"
    UNEXPECTED = "unexpected"


@dataclass(frozen=True, slots=True)
class Drift:
    kind: DriftKind
    identity: tuple[str, str, str]
    baseline: DNSRecord | None
    current: DNSRecord | None

    @property
    def dangling_candidate(self) -> bool:
        """Flag risky target drift, not proof that a target is claimable."""
        record = self.baseline or self.current
        return bool(
            record
            and record.is_dangling_candidate_type
            and self.kind != DriftKind.UNEXPECTED
        )


def _canonical(record: DNSRecord) -> str:
    data = record.to_dict()
    # Route 53 does not assign meaning to ResourceRecords ordering.
    data["values"] = sorted(data["values"])
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _index(records: Iterable[DNSRecord], source: str) -> dict[tuple[str, str, str], DNSRecord]:
    result: dict[tuple[str, str, str], DNSRecord] = {}
    for record in records:
        if record.identity in result:
            name, record_type, identifier = record.identity
            suffix = f" ({identifier})" if identifier else ""
            raise ValidationError(f"duplicate {source} record: {name} {record_type}{suffix}")
        result[record.identity] = record
    return result


def compare_records(
    baseline: Iterable[DNSRecord],
    current: Iterable[DNSRecord],
) -> tuple[Drift, ...]:
    """Return deterministic missing, modified, and unexpected record drift."""
    trusted = _index(baseline, "baseline")
    observed = _index(current, "current")
    drift: list[Drift] = []

    for identity in sorted(trusted.keys() | observed.keys()):
        expected = trusted.get(identity)
        actual = observed.get(identity)
        if expected is None:
            drift.append(Drift(DriftKind.UNEXPECTED, identity, None, actual))
        elif actual is None:
            drift.append(Drift(DriftKind.MISSING, identity, expected, None))
        elif _canonical(expected) != _canonical(actual):
            drift.append(Drift(DriftKind.MODIFIED, identity, expected, actual))
    return tuple(drift)
