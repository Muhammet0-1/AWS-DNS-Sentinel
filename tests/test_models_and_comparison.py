import unittest

from aws_dns_sentinel.comparison import DriftKind, compare_records
from aws_dns_sentinel.exceptions import ValidationError
from aws_dns_sentinel.models import DNSRecord


def record(
    name: str = "www.example.test.",
    record_type: str = "A",
    values: tuple[str, ...] = ("192.0.2.1",),
    ttl: int = 300,
) -> DNSRecord:
    return DNSRecord(name, record_type, values, ttl)


class ModelAndComparisonTests(unittest.TestCase):
    def test_resource_record_value_order_is_ignored(self) -> None:
        baseline = record(values=("192.0.2.1", "192.0.2.2"))
        current = record(values=("192.0.2.2", "192.0.2.1"))
        self.assertEqual(compare_records((baseline,), (current,)), ())

    def test_compares_full_identity_and_configuration(self) -> None:
        a_record = record()
        cname_record = record(record_type="CNAME", values=("target.example.test.",))
        changed_ttl = record(ttl=60)
        drift = compare_records((a_record, cname_record), (changed_ttl,))
        self.assertEqual(
            [item.kind for item in drift],
            [DriftKind.MODIFIED, DriftKind.MISSING],
        )
        self.assertTrue(drift[1].dangling_candidate)

    def test_reports_unexpected_record_without_calling_it_dangling(self) -> None:
        drift = compare_records(
            (),
            (record(record_type="CNAME", values=("target.test.",)),),
        )
        self.assertEqual(drift[0].kind, DriftKind.UNEXPECTED)
        self.assertFalse(drift[0].dangling_candidate)

    def test_alias_record_round_trip(self) -> None:
        raw = {
            "Name": "app.example.test.",
            "Type": "A",
            "AliasTarget": {
                "DNSName": "service.example.test.",
                "HostedZoneId": "ZALIAS123",
                "EvaluateTargetHealth": False,
            },
        }
        self.assertEqual(DNSRecord.from_route53(raw).to_route53(), raw)

    def test_rejects_duplicate_record_identity(self) -> None:
        with self.assertRaisesRegex(ValidationError, "duplicate baseline"):
            compare_records((record(), record()), ())

    def test_rejects_invalid_records(self) -> None:
        with self.assertRaises(ValidationError):
            DNSRecord("example.test", "A", (), 300)
        with self.assertRaises(ValidationError):
            DNSRecord("example.test", "A", ("192.0.2.1",), -1)


if __name__ == "__main__":
    unittest.main()
