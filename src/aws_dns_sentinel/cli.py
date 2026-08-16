"""Command-line interface for safe Route 53 baseline auditing."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from .exceptions import SentinelError, ValidationError
from .reporting import render_text, write_json_report
from .scanner import DNSIntegrityScanner
from .validation import (
    validate_file_path,
    validate_hosted_zone_id,
    validate_json_path,
)

LOGGER = logging.getLogger("aws_dns_sentinel")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-dns-sentinel",
        description="Audit an AWS Route 53 hosted zone against a local baseline.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser("baseline", help="capture a trusted Route 53 baseline")
    baseline.add_argument("--log-file", type=Path, help="optional detailed local log file")
    baseline.add_argument("--zone-id", required=True)
    baseline.add_argument("--baseline", type=Path, default=Path("dns_baseline.json"))
    baseline.add_argument("--overwrite", action="store_true")

    audit = subparsers.add_parser("audit", help="compare Route 53 with a trusted baseline")
    audit.add_argument("--log-file", type=Path, help="optional detailed local log file")
    audit.add_argument("--zone-id", required=True)
    audit.add_argument("--baseline", type=Path, default=Path("dns_baseline.json"))
    audit.add_argument("--report", type=Path, help="write a JSON drift report")
    audit.add_argument(
        "--remediate",
        action="store_true",
        help="prepare or apply conservative baseline UPSERTs (off by default)",
    )
    audit.add_argument(
        "--apply",
        action="store_true",
        help="actually submit remediation; requires --remediate and --confirm-zone-id",
    )
    audit.add_argument(
        "--confirm-zone-id",
        help="exact target zone ID acknowledgement required with --apply",
    )
    return parser


def _configure_logging(log_file: Path | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file is not None:
        validated = validate_file_path(
            log_file,
            allowed_suffixes=frozenset({".log"}),
            for_write=True,
        )
        handlers.append(logging.FileHandler(validated, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
        force=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        _configure_logging(args.log_file)
        if args.command == "baseline":
            validate_json_path(args.baseline, for_write=True)
            scanner = DNSIntegrityScanner(args.zone_id, baseline_file=args.baseline)
            path = scanner.initialize_baseline(overwrite=args.overwrite)
            print(f"Baseline written to {path}")
            return 0

        if args.apply and not args.remediate:
            parser.error("--apply requires --remediate")
        if args.apply and args.confirm_zone_id is None:
            parser.error("--apply requires --confirm-zone-id")
        baseline_path = validate_json_path(args.baseline, must_exist=True)
        if args.report is not None:
            report_path = validate_json_path(args.report, for_write=True)
            same_resolved_path = baseline_path.resolve() == report_path.resolve()
            same_existing_file = report_path.exists() and baseline_path.samefile(report_path)
            if same_resolved_path or same_existing_file:
                raise ValidationError("report path must not refer to the baseline file")
        if args.apply:
            confirmed_zone_id = validate_hosted_zone_id(args.confirm_zone_id)
            if confirmed_zone_id != validate_hosted_zone_id(args.zone_id):
                parser.error("--confirm-zone-id must exactly match --zone-id")
        scanner = DNSIntegrityScanner(
            args.zone_id,
            baseline_file=args.baseline,
            remediation_enabled=args.remediate and args.apply,
        )
        result = scanner.perform_audit(
            remediate=args.remediate,
            dry_run=not args.apply,
            confirmed_zone_id=args.confirm_zone_id,
        )
        print(render_text(result.drift))
        if result.remediation is not None:
            mode = "dry-run" if result.remediation.dry_run else "applied"
            print(
                f"Remediation {mode}: planned={len(result.remediation.planned)} "
                f"applied={len(result.remediation.applied)} "
                f"skipped={len(result.remediation.skipped)}"
            )
        if args.report:
            write_json_report(args.report, result.drift)
            print(f"JSON report written to {args.report}")
        return 0 if result.clean else 1
    except SentinelError as exc:
        LOGGER.error("%s", exc)
        return 2
    except OSError as exc:
        LOGGER.error("local I/O failure: %s", exc)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
