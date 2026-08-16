"""AWS DNS Sentinel public API."""

from .comparison import Drift, DriftKind, compare_records
from .models import DNSRecord
from .scanner import AuditResult, DNSIntegrityScanner

__all__ = [
    "AuditResult",
    "DNSIntegrityScanner",
    "DNSRecord",
    "Drift",
    "DriftKind",
    "compare_records",
]

__version__ = "0.2.0"
