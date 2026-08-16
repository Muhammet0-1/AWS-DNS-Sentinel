import json
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aws_dns_sentinel.baseline import save_baseline
from aws_dns_sentinel.cli import main
from aws_dns_sentinel.models import DNSRecord
from aws_dns_sentinel.reporting import render_text, write_json_report
from aws_dns_sentinel.scanner import DNSIntegrityScanner


class ReadOnlyFakeClient:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.records = records
        self.change_calls = 0

    def list_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        return {"ResourceRecordSets": self.records, "IsTruncated": False}

    def change_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        self.change_calls += 1
        raise AssertionError("default audit must not write to Route 53")


class ReportingAndScannerTests(unittest.TestCase):
    def test_cli_rejects_bad_output_path_before_creating_an_aws_client(self) -> None:
        exit_code = main(
            ["baseline", "--zone-id", "Z123ABC", "--baseline", "baseline.txt"]
        )
        self.assertEqual(exit_code, 2)

    def test_cli_refuses_to_overwrite_baseline_with_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            trusted = DNSRecord("app.example.test", "A", ("192.0.2.1",), 60)
            save_baseline(baseline_path, "Z123ABC", (trusted,))
            original = baseline_path.read_bytes()

            exit_code = main(
                [
                    "audit",
                    "--zone-id",
                    "Z123ABC",
                    "--baseline",
                    str(baseline_path),
                    "--report",
                    str(baseline_path),
                ]
            )

            self.assertEqual(exit_code, 2)
            self.assertEqual(baseline_path.read_bytes(), original)

    def test_scanner_audit_is_read_only_by_default_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_path = root / "baseline.json"
            report_path = root / "report.json"
            trusted = DNSRecord("app.example.test", "A", ("192.0.2.1",), 60)
            save_baseline(baseline_path, "Z123ABC", (trusted,))
            client = ReadOnlyFakeClient(
                [
                    {
                        "Name": "app.example.test.",
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.2"}],
                    }
                ]
            )

            result = DNSIntegrityScanner(
                "Z123ABC",
                client=client,
                baseline_file=baseline_path,
            ).perform_audit()

            self.assertFalse(result.clean)
            self.assertIsNone(result.remediation)
            self.assertEqual(client.change_calls, 0)
            self.assertIn("MODIFIED", render_text(result.drift))
            write_json_report(report_path, result.drift)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["drift_count"], 1)
            self.assertEqual(report["drift"][0]["kind"], "modified")
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
