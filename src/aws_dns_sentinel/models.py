"""Validated DNS record model shared by storage, comparison, and AWS code."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .exceptions import ValidationError
from .validation import (
    validate_domain_name,
    validate_record_type,
    validate_record_value,
)

_POLICY_KEYS = frozenset(
    {
        "Weight",
        "Region",
        "GeoLocation",
        "Failover",
        "MultiValueAnswer",
        "HealthCheckId",
        "TrafficPolicyInstanceId",
        "CidrRoutingConfig",
        "GeoProximityLocation",
    }
)


@dataclass(frozen=True, slots=True)
class DNSRecord:
    """A Route 53 resource record set, normalized for stable comparison."""

    name: str
    record_type: str
    values: tuple[str, ...] = ()
    ttl: int | None = None
    alias_target: Mapping[str, Any] | None = None
    set_identifier: str | None = None
    routing_policy: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", validate_domain_name(self.name))
        object.__setattr__(self, "record_type", validate_record_type(self.record_type))
        if isinstance(self.values, str | bytes) or not isinstance(self.values, Sequence):
            raise ValidationError("record values must be a list or tuple of strings")
        object.__setattr__(
            self,
            "values",
            tuple(validate_record_value(item) for item in self.values),
        )
        if self.ttl is not None and (
            not isinstance(self.ttl, int)
            or isinstance(self.ttl, bool)
            or not 0 <= self.ttl <= 2_147_483_647
        ):
            raise ValidationError("TTL must be an integer between 0 and 2147483647")
        if bool(self.values) == bool(self.alias_target):
            raise ValidationError("record must contain exactly one of values or alias_target")
        if self.alias_target is not None:
            self._validate_alias(self.alias_target)
            if self.ttl is not None:
                raise ValidationError("alias records cannot define a TTL")
        elif self.ttl is None:
            raise ValidationError("non-alias records require a TTL")
        if self.set_identifier is not None and (
            not isinstance(self.set_identifier, str)
            or not self.set_identifier.strip()
            or len(self.set_identifier) > 128
            or any(ord(character) < 32 for character in self.set_identifier)
        ):
            raise ValidationError("set identifier must contain between 1 and 128 characters")
        if not isinstance(self.routing_policy, Mapping):
            raise ValidationError("routing policy must be an object")
        if any(not isinstance(key, str) for key in self.routing_policy):
            raise ValidationError("routing policy field names must be strings")
        unknown = set(self.routing_policy) - _POLICY_KEYS
        if unknown:
            unknown_fields = ", ".join(sorted(unknown))
            raise ValidationError(f"unsupported Route 53 routing fields: {unknown_fields}")
        try:
            json.dumps(dict(self.routing_policy), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValidationError("routing policy must contain valid JSON values") from exc
        self._validate_routing_policy(self.routing_policy)

    @staticmethod
    def _validate_alias(alias: Mapping[str, Any]) -> None:
        if not isinstance(alias, Mapping):
            raise ValidationError("AliasTarget must be an object")
        expected = {"DNSName", "HostedZoneId", "EvaluateTargetHealth"}
        if set(alias) != expected:
            raise ValidationError(
                "AliasTarget must contain DNSName, HostedZoneId, and EvaluateTargetHealth"
            )
        validate_domain_name(alias["DNSName"], allow_wildcard=False)
        validate_hosted_zone = alias["HostedZoneId"]
        if not isinstance(validate_hosted_zone, str) or not validate_hosted_zone.strip():
            raise ValidationError("AliasTarget HostedZoneId must be a non-empty string")
        if not isinstance(alias["EvaluateTargetHealth"], bool):
            raise ValidationError("AliasTarget EvaluateTargetHealth must be boolean")

    @staticmethod
    def _validate_routing_policy(policy: Mapping[str, Any]) -> None:
        if "Weight" in policy and (
            not isinstance(policy["Weight"], int) or isinstance(policy["Weight"], bool)
        ):
            raise ValidationError("routing Weight must be an integer")
        for key in ("Region", "Failover", "HealthCheckId", "TrafficPolicyInstanceId"):
            if key in policy and (
                not isinstance(policy[key], str) or not policy[key].strip()
            ):
                raise ValidationError(f"routing {key} must be a non-empty string")
        if "MultiValueAnswer" in policy and not isinstance(policy["MultiValueAnswer"], bool):
            raise ValidationError("routing MultiValueAnswer must be boolean")
        for key in ("GeoLocation", "CidrRoutingConfig", "GeoProximityLocation"):
            if key in policy and not isinstance(policy[key], Mapping):
                raise ValidationError(f"routing {key} must be an object")

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.name, self.record_type, self.set_identifier or "")

    @property
    def is_dangling_candidate_type(self) -> bool:
        return self.record_type in {"CNAME", "NS"} or self.alias_target is not None

    def to_route53(self) -> dict[str, Any]:
        result: dict[str, Any] = {"Name": self.name, "Type": self.record_type}
        if self.set_identifier is not None:
            result["SetIdentifier"] = self.set_identifier
        result.update(dict(self.routing_policy))
        if self.alias_target is not None:
            result["AliasTarget"] = dict(self.alias_target)
        else:
            result["TTL"] = self.ttl
            result["ResourceRecords"] = [{"Value": value} for value in self.values]
        return result

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "type": self.record_type,
            "values": list(self.values),
            "ttl": self.ttl,
        }
        if self.alias_target is not None:
            data["alias_target"] = dict(self.alias_target)
        if self.set_identifier is not None:
            data["set_identifier"] = self.set_identifier
        if self.routing_policy:
            data["routing_policy"] = dict(self.routing_policy)
        return data

    @classmethod
    def from_route53(cls, data: Mapping[str, Any]) -> DNSRecord:
        try:
            allowed = {
                "Name",
                "Type",
                "TTL",
                "ResourceRecords",
                "AliasTarget",
                "SetIdentifier",
            } | _POLICY_KEYS
            if set(data) - allowed:
                raise ValidationError("Route 53 record contains unsupported fields")
            raw_values = data.get("ResourceRecords", ())
            if not isinstance(raw_values, list | tuple):
                raise ValidationError("Route 53 ResourceRecords must be a list")
            values = tuple(item["Value"] for item in raw_values)
            routing = {key: data[key] for key in _POLICY_KEYS if key in data}
            return cls(
                name=data["Name"],
                record_type=data["Type"],
                values=values,
                ttl=data.get("TTL"),
                alias_target=data.get("AliasTarget"),
                set_identifier=data.get("SetIdentifier"),
                routing_policy=routing,
            )
        except (KeyError, TypeError) as exc:
            raise ValidationError("malformed Route 53 resource record set") from exc

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DNSRecord:
        try:
            allowed = {
                "name",
                "type",
                "values",
                "ttl",
                "alias_target",
                "set_identifier",
                "routing_policy",
            }
            if set(data) - allowed:
                raise ValidationError("baseline DNS record contains unsupported fields")
            raw_values = data.get("values", ())
            if not isinstance(raw_values, list):
                raise ValidationError("baseline DNS record values must be a list")
            return cls(
                name=data["name"],
                record_type=data["type"],
                values=tuple(raw_values),
                ttl=data.get("ttl"),
                alias_target=data.get("alias_target"),
                set_identifier=data.get("set_identifier"),
                routing_policy=data.get("routing_policy", {}),
            )
        except (KeyError, TypeError) as exc:
            raise ValidationError("malformed baseline DNS record") from exc

    @classmethod
    def from_legacy_dict(cls, data: Mapping[str, Any]) -> DNSRecord:
        try:
            allowed = {"Name", "Type", "Value", "TTL"}
            if set(data) - allowed:
                raise ValidationError("legacy baseline DNS record contains unsupported fields")
            raw_values = data.get("Value", ())
            if not isinstance(raw_values, list):
                raise ValidationError("legacy baseline DNS record Value must be a list")
            if not raw_values:
                raise ValidationError(
                    "legacy baseline record has no values; the legacy format cannot "
                    "preserve alias targets, so recapture the baseline with the "
                    "baseline command and --overwrite"
                )
            return cls(
                name=data["Name"],
                record_type=data["Type"],
                values=tuple(raw_values),
                ttl=data.get("TTL", 300),
            )
        except (KeyError, TypeError) as exc:
            raise ValidationError("malformed legacy baseline DNS record") from exc
