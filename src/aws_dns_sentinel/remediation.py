"""Opt-in remediation with dry-run and exact-zone confirmation safeguards."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from .comparison import Drift, DriftKind
from .exceptions import RemediationBlockedError
from .models import DNSRecord
from .validation import validate_hosted_zone_id

LOGGER = logging.getLogger(__name__)
_PROTECTED_TYPES = frozenset({"NS", "SOA"})


class Route53Writer(Protocol):
    zone_id: str

    def upsert_record(self, record: DNSRecord) -> None: ...


@dataclass(frozen=True, slots=True)
class RemediationAction:
    record: DNSRecord
    reason: DriftKind


@dataclass(frozen=True, slots=True)
class RemediationResult:
    planned: tuple[RemediationAction, ...]
    applied: tuple[RemediationAction, ...]
    skipped: tuple[Drift, ...]
    dry_run: bool


def build_remediation_plan(drift: tuple[Drift, ...]) -> tuple[RemediationAction, ...]:
    """Plan conservative UPSERTs; never delete unexpected or alter NS/SOA records."""
    actions: list[RemediationAction] = []
    for item in drift:
        if (
            item.kind in {DriftKind.MISSING, DriftKind.MODIFIED}
            and item.baseline is not None
            and item.baseline.record_type not in _PROTECTED_TYPES
        ):
            actions.append(RemediationAction(item.baseline, item.kind))
    return tuple(actions)


class Remediator:
    def __init__(self, service: Route53Writer, *, changes_enabled: bool = False) -> None:
        self._service = service
        self._changes_enabled = changes_enabled

    def execute(
        self,
        drift: tuple[Drift, ...],
        *,
        dry_run: bool = True,
        confirmed_zone_id: str | None = None,
    ) -> RemediationResult:
        plan = build_remediation_plan(drift)
        planned_records = {action.record.identity for action in plan}
        skipped = tuple(
            item
            for item in drift
            if item.baseline is None or item.baseline.identity not in planned_records
        )
        LOGGER.info(
            "Remediation plan prepared: planned=%d skipped=%d dry_run=%s",
            len(plan),
            len(skipped),
            dry_run,
        )
        if dry_run:
            return RemediationResult(plan, (), skipped, True)
        if not self._changes_enabled:
            raise RemediationBlockedError("remediation is disabled; opt in explicitly")
        if confirmed_zone_id is None:
            raise RemediationBlockedError("an exact hosted-zone confirmation is required")
        if validate_hosted_zone_id(confirmed_zone_id) != self._service.zone_id:
            raise RemediationBlockedError("hosted-zone confirmation does not match the target")

        applied: list[RemediationAction] = []
        for action in plan:
            LOGGER.warning(
                "Applying remediation: zone=%s record=%s type=%s reason=%s",
                self._service.zone_id,
                action.record.name,
                action.record.record_type,
                action.reason.value,
            )
            self._service.upsert_record(action.record)
            applied.append(action)
        return RemediationResult(plan, tuple(applied), skipped, False)
