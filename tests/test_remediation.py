import unittest
from dataclasses import dataclass, field

from aws_dns_sentinel.comparison import Drift, DriftKind
from aws_dns_sentinel.exceptions import RemediationBlockedError
from aws_dns_sentinel.models import DNSRecord
from aws_dns_sentinel.remediation import Remediator, build_remediation_plan


@dataclass
class FakeService:
    zone_id: str = "Z123ABC"
    upserts: list[DNSRecord] = field(default_factory=list)

    def upsert_record(self, record: DNSRecord) -> None:
        self.upserts.append(record)


def missing(record_type: str = "A") -> Drift:
    value = "target.example.test." if record_type in {"CNAME", "NS"} else "192.0.2.1"
    record = DNSRecord("app.example.test", record_type, (value,), 300)
    return Drift(DriftKind.MISSING, record.identity, record, None)


class RemediationTests(unittest.TestCase):
    def test_dry_run_never_changes_aws_even_when_changes_enabled(self) -> None:
        service = FakeService()
        result = Remediator(service, changes_enabled=True).execute((missing(),), dry_run=True)
        self.assertEqual(len(result.planned), 1)
        self.assertEqual(result.applied, ())
        self.assertEqual(service.upserts, [])

    def test_default_lock_blocks_apply(self) -> None:
        service = FakeService()
        with self.assertRaisesRegex(RemediationBlockedError, "disabled"):
            Remediator(service).execute(
                (missing(),),
                dry_run=False,
                confirmed_zone_id=service.zone_id,
            )
        self.assertEqual(service.upserts, [])

    def test_exact_zone_confirmation_is_required(self) -> None:
        service = FakeService()
        remediator = Remediator(service, changes_enabled=True)
        with self.assertRaisesRegex(RemediationBlockedError, "confirmation"):
            remediator.execute((missing(),), dry_run=False)
        with self.assertRaisesRegex(RemediationBlockedError, "does not match"):
            remediator.execute(
                (missing(),),
                dry_run=False,
                confirmed_zone_id="Z999XYZ",
            )
        self.assertEqual(service.upserts, [])

    def test_apply_requires_all_safety_conditions(self) -> None:
        service = FakeService()
        result = Remediator(service, changes_enabled=True).execute(
            (missing(),),
            dry_run=False,
            confirmed_zone_id=service.zone_id,
        )
        self.assertEqual(result.applied, result.planned)
        self.assertEqual(len(service.upserts), 1)

    def test_plan_never_changes_ns_soa_or_deletes_unexpected_records(self) -> None:
        unexpected = missing()
        unexpected = Drift(
            DriftKind.UNEXPECTED,
            unexpected.identity,
            None,
            unexpected.baseline,
        )
        plan = build_remediation_plan((missing("NS"), missing("SOA"), unexpected))
        self.assertEqual(plan, ())


if __name__ == "__main__":
    unittest.main()
