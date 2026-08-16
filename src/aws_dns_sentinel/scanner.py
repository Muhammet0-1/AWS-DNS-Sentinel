"""Application service coordinating AWS reads, baseline comparison, and remediation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .aws import Route53Client, Route53Service, create_route53_client
from .baseline import Baseline, load_baseline, save_baseline
from .comparison import Drift, compare_records
from .models import DNSRecord
from .remediation import RemediationResult, Remediator
from .validation import validate_hosted_zone_id


@dataclass(frozen=True, slots=True)
class AuditResult:
    drift: tuple[Drift, ...]
    remediation: RemediationResult | None = None

    @property
    def clean(self) -> bool:
        return not self.drift


class DNSIntegrityScanner:
    """High-level API; AWS writes remain disabled unless explicitly enabled."""

    def __init__(
        self,
        zone_id: str,
        *,
        client: Route53Client | None = None,
        baseline_file: str | Path = "dns_baseline.json",
        remediation_enabled: bool = False,
    ) -> None:
        self.zone_id = validate_hosted_zone_id(zone_id)
        self.baseline_file = Path(baseline_file)
        route53_client = client if client is not None else create_route53_client()
        self._service = Route53Service(route53_client, self.zone_id)
        self._remediation_enabled = remediation_enabled

    def initialize_baseline(self, *, overwrite: bool = False) -> Path:
        records = self.fetch_current_state()
        return save_baseline(
            self.baseline_file,
            self.zone_id,
            records,
            overwrite=overwrite,
        )

    def fetch_current_state(self) -> tuple[DNSRecord, ...]:
        """Return the current validated Route 53 records (legacy API name)."""
        return self._service.list_records()

    def load_baseline(self) -> Baseline:
        return load_baseline(self.baseline_file, self.zone_id)

    def perform_audit(
        self,
        *,
        remediate: bool = False,
        dry_run: bool = True,
        confirmed_zone_id: str | None = None,
    ) -> AuditResult:
        baseline = self.load_baseline()
        current = self.fetch_current_state()
        drift = compare_records(baseline.records, current)
        remediation = None
        if remediate:
            remediation = Remediator(
                self._service,
                changes_enabled=self._remediation_enabled,
            ).execute(
                drift,
                dry_run=dry_run,
                confirmed_zone_id=confirmed_zone_id,
            )
        return AuditResult(drift, remediation)
