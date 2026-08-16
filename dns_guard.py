#!/usr/bin/env python3
"""Backward-compatible import for the original single-file project.

Install the package first (``python -m pip install -e .``), then prefer the
``aws-dns-sentinel`` command. Importing ``DNSIntegrityScanner`` from this module
continues to work for existing callers.
"""

from aws_dns_sentinel.cli import main
from aws_dns_sentinel.scanner import DNSIntegrityScanner

__all__ = ["DNSIntegrityScanner"]


if __name__ == "__main__":
    raise SystemExit(main())
