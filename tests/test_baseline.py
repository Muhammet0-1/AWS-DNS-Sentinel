import json
import stat
import tempfile
import unittest
from pathlib import Path

from aws_dns_sentinel.baseline import load_baseline, save_baseline
from aws_dns_sentinel.exceptions import BaselineError
from aws_dns_sentinel.models import DNSRecord


class BaselineTests(unittest.TestCase):
    def test_save_and_load_versioned_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            records = (DNSRecord("example.test", "A", ("192.0.2.1",), 300),)
            save_baseline(path, "Z123ABC", records)
            loaded = load_baseline(path, "Z123ABC")
            self.assertEqual(loaded.records, records)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaisesRegex(BaselineError, "already exists"):
                save_baseline(path, "Z123ABC", records)

    def test_reads_original_legacy_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "Name": "example.test.",
                            "Type": "A",
                            "Value": ["192.0.2.1"],
                            "TTL": 60,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            loaded = load_baseline(path, "Z123ABC")
            self.assertIsNone(loaded.hosted_zone_id)
            self.assertEqual(loaded.records[0].ttl, 60)

    def test_legacy_alias_shape_requests_safe_baseline_recapture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-alias.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "Name": "alias.example.test.",
                            "Type": "A",
                            "Value": [],
                            "TTL": 300,
                        }
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                BaselineError,
                "legacy format cannot preserve alias targets.*--overwrite",
            ):
                load_baseline(path, "Z123ABC")

    def test_rejects_corrupt_json_and_wrong_zone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corrupt = root / "corrupt.json"
            corrupt.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "cannot load"):
                load_baseline(corrupt)

            baseline = root / "baseline.json"
            save_baseline(
                baseline,
                "Z123ABC",
                (DNSRecord("x.test", "A", ("192.0.2.1",), 60),),
            )
            with self.assertRaisesRegex(BaselineError, "different hosted zone"):
                load_baseline(baseline, "Z999XYZ")


if __name__ == "__main__":
    unittest.main()
