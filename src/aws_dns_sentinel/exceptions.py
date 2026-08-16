"""Domain-specific exceptions exposed by AWS DNS Sentinel."""


class SentinelError(Exception):
    """Base class for expected, user-actionable failures."""


class ValidationError(SentinelError):
    """An input does not meet the expected format or safety constraints."""


class BaselineError(SentinelError):
    """A baseline cannot be read, validated, or written safely."""


class AWSOperationError(SentinelError):
    """A Route 53 operation failed."""


class AWSCredentialsError(AWSOperationError):
    """AWS credentials are absent or unusable."""


class AWSPermissionError(AWSOperationError):
    """The caller lacks a required AWS permission."""


class AWSTimeoutError(AWSOperationError):
    """An AWS request timed out."""


class RemediationBlockedError(SentinelError):
    """A remediation safety condition was not met."""
