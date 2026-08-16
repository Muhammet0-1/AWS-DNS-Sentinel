import unittest
from typing import Any

from aws_dns_sentinel.aws import Route53Service
from aws_dns_sentinel.exceptions import (
    AWSCredentialsError,
    AWSOperationError,
    AWSPermissionError,
    AWSTimeoutError,
)
from aws_dns_sentinel.models import DNSRecord


class FakeClient:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.requests: list[dict[str, Any]] = []

    def list_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        return self.pages.pop(0)

    def change_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("tests must not make Route 53 changes")


class RecordingClient(FakeClient):
    def __init__(self) -> None:
        super().__init__([])
        self.change_requests: list[dict[str, Any]] = []

    def change_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        self.change_requests.append(kwargs)
        return {"ChangeInfo": {"Id": "mock-change", "Status": "PENDING"}}


class RaisingClient(FakeClient):
    def __init__(self, exception: Exception) -> None:
        super().__init__([])
        self.exception = exception

    def list_resource_record_sets(self, **kwargs: Any) -> dict[str, Any]:
        raise self.exception


class AWSTests(unittest.TestCase):
    def test_upsert_uses_mock_client_with_expected_zone(self) -> None:
        client = RecordingClient()
        service = Route53Service(client, "Z123ABC")
        service.upsert_record(DNSRecord("app.example.test", "A", ("192.0.2.1",), 60))
        self.assertEqual(client.change_requests[0]["HostedZoneId"], "Z123ABC")
        change = client.change_requests[0]["ChangeBatch"]["Changes"][0]
        self.assertEqual(change["Action"], "UPSERT")

    def test_lists_paginated_records_with_mock_client(self) -> None:
        client = FakeClient(
            [
                {
                    "ResourceRecordSets": [
                        {
                            "Name": "a.example.test.",
                            "Type": "A",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": "192.0.2.1"}],
                        }
                    ],
                    "IsTruncated": True,
                    "NextRecordName": "b.example.test.",
                    "NextRecordType": "AAAA",
                },
                {
                    "ResourceRecordSets": [
                        {
                            "Name": "b.example.test.",
                            "Type": "AAAA",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": "2001:db8::1"}],
                        }
                    ],
                    "IsTruncated": False,
                },
            ]
        )
        records = Route53Service(client, "Z123ABC").list_records()
        self.assertEqual(len(records), 2)
        self.assertEqual(client.requests[1]["StartRecordName"], "b.example.test.")

    def test_pagination_clears_a_stale_record_identifier(self) -> None:
        def page(name: str, *, truncated: bool, **continuation: Any) -> dict[str, Any]:
            return {
                "ResourceRecordSets": [
                    {
                        "Name": name,
                        "Type": "A",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": "192.0.2.1"}],
                    }
                ],
                "IsTruncated": truncated,
                **continuation,
            }

        client = FakeClient(
            [
                page(
                    "a.example.test.",
                    truncated=True,
                    NextRecordName="b.example.test.",
                    NextRecordType="A",
                    NextRecordIdentifier="weighted-b",
                ),
                page(
                    "b.example.test.",
                    truncated=True,
                    NextRecordName="c.example.test.",
                    NextRecordType="A",
                ),
                page("c.example.test.", truncated=False),
            ]
        )

        records = Route53Service(client, "Z123ABC").list_records()

        self.assertEqual(len(records), 3)
        self.assertEqual(client.requests[1]["StartRecordIdentifier"], "weighted-b")
        self.assertNotIn("StartRecordIdentifier", client.requests[2])

    def test_translates_missing_credentials_without_network(self) -> None:
        no_credentials = type("NoCredentialsError", (Exception,), {})()
        with self.assertRaises(AWSCredentialsError):
            Route53Service(RaisingClient(no_credentials), "Z123ABC").list_records()

    def test_translates_permission_error_without_leaking_message(self) -> None:
        denied_type = type("ClientError", (Exception,), {})
        denied = denied_type("secret-looking request context")
        denied.response = {"Error": {"Code": "AccessDenied", "Message": "sensitive"}}
        with self.assertRaises(AWSPermissionError) as raised:
            Route53Service(RaisingClient(denied), "Z123ABC").list_records()
        self.assertNotIn("sensitive", str(raised.exception))

    def test_translates_timeout_without_network(self) -> None:
        timeout = type("ConnectTimeoutError", (Exception,), {})()
        with self.assertRaises(AWSTimeoutError):
            Route53Service(RaisingClient(timeout), "Z123ABC").list_records()

    def test_rejects_malformed_aws_page(self) -> None:
        with self.assertRaisesRegex(AWSOperationError, "malformed"):
            Route53Service(FakeClient([{}]), "Z123ABC").list_records()


if __name__ == "__main__":
    unittest.main()
