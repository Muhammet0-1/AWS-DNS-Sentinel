"""Validation and normalization for untrusted user and AWS inputs."""

from __future__ import annotations

import re
from pathlib import Path

from .exceptions import ValidationError

_ZONE_ID = re.compile(r"^Z[A-Z0-9]{1,31}$")
_RECORD_TYPES = frozenset(
    {
        "A",
        "AAAA",
        "CAA",
        "CNAME",
        "DS",
        "HTTPS",
        "MX",
        "NAPTR",
        "NS",
        "PTR",
        "SOA",
        "SPF",
        "SRV",
        "SSHFP",
        "SVCB",
        "TLSA",
        "TXT",
    }
)


def validate_hosted_zone_id(value: str) -> str:
    """Return a normalized Route 53 hosted-zone ID."""
    if not isinstance(value, str):
        raise ValidationError("hosted zone ID must be a string")
    normalized = value.strip()
    if normalized.startswith("/hostedzone/"):
        normalized = normalized.removeprefix("/hostedzone/")
    if not _ZONE_ID.fullmatch(normalized):
        raise ValidationError("invalid Route 53 hosted zone ID")
    return normalized


def validate_domain_name(value: str, *, allow_wildcard: bool = True) -> str:
    """Normalize a DNS name to lowercase ASCII with a trailing dot."""
    if not isinstance(value, str):
        raise ValidationError("DNS name must be a string")
    candidate = value.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise ValidationError("DNS name must contain between 1 and 253 characters")

    labels = candidate.split(".")
    ascii_labels: list[str] = []
    for index, label in enumerate(labels):
        if label == "*" and allow_wildcard and index == 0:
            ascii_labels.append(label)
            continue
        if not label:
            raise ValidationError("DNS name contains an empty label")
        try:
            ascii_label = label.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValidationError("DNS name contains an invalid internationalized label") from exc
        if len(ascii_label) > 63:
            raise ValidationError("DNS label exceeds 63 characters")
        if not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", ascii_label):
            raise ValidationError(f"invalid DNS label: {label!r}")
        ascii_labels.append(ascii_label)
    normalized = ".".join(ascii_labels) + "."
    if len(normalized) > 254:  # 253 characters plus the root-label dot.
        raise ValidationError("normalized DNS name exceeds 253 characters")
    return normalized


def validate_record_type(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("DNS record type must be a string")
    normalized = value.strip().upper()
    if normalized not in _RECORD_TYPES:
        raise ValidationError(f"unsupported DNS record type: {normalized or '<empty>'}")
    return normalized


def validate_record_value(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("DNS record value must be a string")
    if not value or len(value) > 4_000:
        raise ValidationError("DNS record value must contain between 1 and 4000 characters")
    if any(ord(character) < 32 and character not in "\t" for character in value):
        raise ValidationError("DNS record value contains control characters")
    return value


def validate_file_path(
    value: str | Path,
    *,
    allowed_suffixes: frozenset[str] | None = None,
    must_exist: bool = False,
    for_write: bool = False,
) -> Path:
    """Validate a file path without silently creating parent directories."""
    raw = str(value)
    if not raw or "\x00" in raw:
        raise ValidationError("file path is empty or contains a NUL byte")
    path = Path(raw).expanduser()
    if allowed_suffixes is not None and path.suffix.lower() not in allowed_suffixes:
        expected = ", ".join(sorted(allowed_suffixes))
        raise ValidationError(f"file path must use one of these extensions: {expected}")
    if path.exists() and path.is_dir():
        raise ValidationError("file path points to a directory")
    if must_exist and not path.is_file():
        raise ValidationError(f"file does not exist: {path}")
    parent = path.parent
    if for_write and not parent.is_dir():
        raise ValidationError(f"parent directory does not exist: {parent}")
    if for_write and path.is_symlink():
        raise ValidationError("refusing to overwrite a symbolic link")
    return path


def validate_json_path(
    value: str | Path,
    *,
    must_exist: bool = False,
    for_write: bool = False,
) -> Path:
    return validate_file_path(
        value,
        allowed_suffixes=frozenset({".json"}),
        must_exist=must_exist,
        for_write=for_write,
    )
