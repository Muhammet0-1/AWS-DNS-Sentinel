import tempfile
import unittest
from pathlib import Path

from aws_dns_sentinel.exceptions import ValidationError
from aws_dns_sentinel.validation import (
    validate_domain_name,
    validate_hosted_zone_id,
    validate_json_path,
)


class ValidationTests(unittest.TestCase):
    def test_rejects_invalid_zone_ids(self) -> None:
        for value in ("", "hostedzone/Z123", "Z!23", "12345", "Z space"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_hosted_zone_id(value)

    def test_normalizes_zone_id_and_international_domain(self) -> None:
        self.assertEqual(validate_hosted_zone_id(" /hostedzone/Z123ABC "), "Z123ABC")
        self.assertEqual(validate_domain_name("Örnek.COM"), "xn--rnek-4qa.com.")

    def test_rejects_invalid_domains(self) -> None:
        for value in ("", ".example.com", "bad label.example", "foo..example", "foo.*.example"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_domain_name(value)

    def test_validates_json_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValidationError, r"\.json"):
                validate_json_path(root / "baseline.txt", for_write=True)
            with self.assertRaisesRegex(ValidationError, "parent"):
                validate_json_path(root / "missing" / "baseline.json", for_write=True)


if __name__ == "__main__":
    unittest.main()
