"""Small Route 53 adapter with bounded timeouts and translated failures."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Protocol, cast

from .exceptions import (
    AWSCredentialsError,
    AWSOperationError,
    AWSPermissionError,
    AWSTimeoutError,
    ValidationError,
)
from .models import DNSRecord
from .validation import validate_hosted_zone_id

LOGGER = logging.getLogger(__name__)


class Route53Client(Protocol):
    def list_resource_record_sets(self, **kwargs: Any) -> Mapping[str, Any]: ...

    def change_resource_record_sets(self, **kwargs: Any) -> Mapping[str, Any]: ...


def create_route53_client() -> Route53Client:
    """Create the production boto3 client only when the CLI needs it."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:  # pragma: no cover - packaging/runtime guard
        raise AWSOperationError("boto3 is not installed") from exc
    try:
        client = boto3.client(
            "route53",
            config=Config(
                connect_timeout=5,
                read_timeout=15,
                retries={"mode": "standard", "total_max_attempts": 3},
            ),
        )
    except Exception as exc:
        raise _translate_aws_error(exc, "create Route 53 client") from exc
    return cast(Route53Client, client)


def _translate_aws_error(exc: Exception, operation: str) -> AWSOperationError:
    """Map botocore errors without echoing credential-bearing request details."""
    name = type(exc).__name__
    response = getattr(exc, "response", {})
    error = response.get("Error", {}) if isinstance(response, Mapping) else {}
    code = str(error.get("Code", name)) if isinstance(error, Mapping) else name

    if name in {"NoCredentialsError", "PartialCredentialsError", "CredentialRetrievalError"}:
        return AWSCredentialsError(f"{operation} failed: AWS credentials are unavailable")
    if code in {
        "AccessDenied",
        "AccessDeniedException",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "UnrecognizedClientException",
    }:
        return AWSPermissionError(f"{operation} failed: AWS authorization was denied ({code})")
    if name in {
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "EndpointConnectionError",
        "ConnectionClosedError",
    }:
        return AWSTimeoutError(f"{operation} failed: AWS endpoint timed out or was unreachable")
    return AWSOperationError(f"{operation} failed with AWS error code {code}")


class Route53Service:
    def __init__(self, client: Route53Client, zone_id: str) -> None:
        self._client = client
        self.zone_id = validate_hosted_zone_id(zone_id)

    def list_records(self) -> tuple[DNSRecord, ...]:
        request: dict[str, Any] = {"HostedZoneId": self.zone_id}
        records: list[DNSRecord] = []
        try:
            while True:
                page = self._client.list_resource_record_sets(**request)
                raw_records = page.get("ResourceRecordSets")
                if not isinstance(raw_records, list):
                    raise AWSOperationError("Route 53 returned a malformed record-set page")
                records.extend(DNSRecord.from_route53(item) for item in raw_records)
                if not page.get("IsTruncated", False):
                    break
                next_name = page.get("NextRecordName")
                next_type = page.get("NextRecordType")
                if not isinstance(next_name, str) or not isinstance(next_type, str):
                    raise AWSOperationError("Route 53 returned invalid pagination data")
                request["StartRecordName"] = next_name
                request["StartRecordType"] = next_type
                next_identifier = page.get("NextRecordIdentifier")
                if next_identifier is None:
                    request.pop("StartRecordIdentifier", None)
                elif isinstance(next_identifier, str) and next_identifier:
                    request["StartRecordIdentifier"] = next_identifier
                else:
                    raise AWSOperationError("Route 53 returned invalid pagination data")
        except AWSOperationError:
            raise
        except ValidationError as exc:
            raise AWSOperationError(f"Route 53 returned an invalid DNS record: {exc}") from exc
        except Exception as exc:
            raise _translate_aws_error(exc, "list Route 53 records") from exc
        LOGGER.info("Fetched %d Route 53 record sets from zone %s", len(records), self.zone_id)
        return tuple(records)

    def upsert_record(self, record: DNSRecord) -> None:
        try:
            self._client.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch={
                    "Comment": "AWS DNS Sentinel explicit baseline remediation",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": record.to_route53(),
                        }
                    ],
                },
            )
        except Exception as exc:
            operation = f"remediate {record.name} {record.record_type}"
            raise _translate_aws_error(exc, operation) from exc
        LOGGER.warning("Submitted Route 53 UPSERT for %s %s", record.name, record.record_type)
