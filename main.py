#!/usr/bin/env python3
"""
main.py
-------
Entrypoint for the IMDSv2 Compliance Validator.

Orchestrates:
  1. Config parsing (argparse)
  2. Account/session resolution  (modules.accounts)
  3. Parallel EC2 scanning       (modules.inspector)
  4. Report generation           (modules.reporter)

All operations are READ-ONLY.

Usage examples
--------------
# Single account, all instances in one region:
  python3 main.py --regions us-east-1

# Multi-region:
  python3 main.py --regions us-east-1 us-west-2 eu-west-1

# AWS Organizations — scan every member account:
  python3 main.py --org --role-name IMDSv2ValidatorRole --regions us-east-1

# Explicit account list (assume same role in each):
  python3 main.py --account-ids 111122223333 444455556666 --role-name IMDSv2ValidatorRole --regions us-east-1

# Specific instances only:
  python3 main.py --regions us-east-1 --instance-ids i-0abc i-0def

# Output options (table | json | csv | html | all):
  python3 main.py --regions us-east-1 --output all

# Show only non-compliant + needs-review:
  python3 main.py --regions us-east-1 --non-compliant-only

# Full per-instance detail:
  python3 main.py --regions us-east-1 --detail
"""

import argparse
import sys

# ---------------------------------------------------------------------------
# Dependency guard
# ---------------------------------------------------------------------------
try:
    import boto3  # noqa: F401
except ImportError:
    print("[ERROR] boto3 is required. Run: pip install boto3 tabulate")
    sys.exit(1)

from modules.core import Config, setup_logging, now_utc
from modules.accounts import resolve_targets, run_parallel
from modules.inspector import scan_target
from modules.reporter import generate_reports


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="imdsv2_validator",
        description="Read-only EC2 IMDSv2 compliance validator — single, multi-account, and AWS Organizations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single account
  python3 main.py --regions us-east-1

  # All accounts in an AWS Organization
  python3 main.py --org --role-name IMDSv2ValidatorRole --regions us-east-1 us-west-2

  # Specific accounts
  python3 main.py --account-ids 111122223333 444455556666 \\
                  --role-name IMDSv2ValidatorRole --regions us-east-1

  # Generate all output formats
  python3 main.py --regions us-east-1 --output all

  # Only show problem instances with full detail
  python3 main.py --regions us-east-1 --non-compliant-only --detail
        """,
    )

    # ── Scope ──────────────────────────────────────────────────────────────
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--org", action="store_true",
        help="Discover and scan all ACTIVE accounts in the AWS Organization",
    )
    scope.add_argument(
        "--account-ids", nargs="+", metavar="ID",
        help="Explicit list of account IDs to scan (assumes a role in each)",
    )

    parser.add_argument(
        "--regions", nargs="+", metavar="REGION", default=["us-east-1"],
        help="One or more AWS regions to scan (default: us-east-1)",
    )
    parser.add_argument(
        "--instance-ids", nargs="+", metavar="ID",
        help="Limit scan to specific instance IDs",
    )

    # ── Cross-account role ─────────────────────────────────────────────────
    parser.add_argument(
        "--role-name", default="IMDSv2ValidatorRole", metavar="ROLE",
        help="IAM role name to assume in each target account (default: IMDSv2ValidatorRole)",
    )
    parser.add_argument(
        "--profile", default=None, metavar="PROFILE",
        help="AWS CLI named profile for the management/source account",
    )

    # ── Output ─────────────────────────────────────────────────────────────
    parser.add_argument(
        "--output", choices=["table", "json", "csv", "html", "all"], default="table",
        help="Output format (default: table). 'all' writes json+csv+html",
    )
    parser.add_argument(
        "--output-dir", default="reports", metavar="DIR",
        help="Directory for file reports (default: reports/)",
    )
    parser.add_argument(
        "--report-prefix", default="imdsv2_report", metavar="PREFIX",
        help="File name prefix for reports (default: imdsv2_report)",
    )
    parser.add_argument(
        "--non-compliant-only", action="store_true",
        help="Only show NON_COMPLIANT and NEEDS_REVIEW instances",
    )
    parser.add_argument(
        "--detail", action="store_true",
        help="Print full per-instance detail block to console",
    )

    # ── Performance ────────────────────────────────────────────────────────
    parser.add_argument(
        "--max-workers", type=int, default=5, metavar="N",
        help="Parallel threads for account scanning (default: 5)",
    )

    # ── Misc ───────────────────────────────────────────────────────────────
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG logging",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Config builder
# ---------------------------------------------------------------------------

def build_config(args: argparse.Namespace) -> Config:
    cfg = Config(
        regions=args.regions,
        account_ids=args.account_ids or [],
        use_org=args.org,
        org_role_name=args.role_name,
        management_profile=args.profile,
        instance_ids=args.instance_ids or [],
        non_compliant_only=args.non_compliant_only,
        output_format=args.output,
        output_dir=args.output_dir,
        report_prefix=args.report_prefix,
        detail=args.detail,
        max_workers=args.max_workers,
    )
    cfg.validate()
    return cfg


# ---------------------------------------------------------------------------
# Worker closure (binds config so it can be passed to run_parallel)
# ---------------------------------------------------------------------------

def make_worker(config: Config):
    """Return a worker function that scans one AccountTarget."""
    def _worker(target):
        return scan_target(target, instance_ids=config.instance_ids)
    return _worker


# ---------------------------------------------------------------------------
# Main orchestration
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    log = setup_logging(verbose=args.verbose)

    log.info("=" * 60)
    log.info("  EC2 IMDSv2 Compliance Validator — READ-ONLY")
    log.info("  Started : %s", now_utc().strftime("%Y-%m-%d %H:%M:%S UTC"))
    log.info("=" * 60)

    # 1. Build config
    try:
        config = build_config(args)
    except ValueError as exc:
        log.error("Configuration error: %s", exc)
        sys.exit(1)

    log.info("Regions   : %s", ", ".join(config.regions))
    log.info("Output    : %s → %s/", config.output_format, config.output_dir)

    # 2. Resolve account targets
    log.info("Resolving account targets...")
    targets = resolve_targets(config)
    if not targets:
        log.error("No valid targets to scan. Exiting.")
        sys.exit(1)

    valid_targets = [t for t in targets if t.error is None]
    log.info(
        "Scanning %d target(s) across %d account(s) and %d region(s).",
        len(valid_targets),
        len({t.account_id for t in valid_targets}),
        len({t.region for t in valid_targets}),
    )

    # 3. Parallel scan
    log.info("Starting parallel scan (max_workers=%d)...", config.max_workers)
    worker = make_worker(config)
    all_reports = run_parallel(valid_targets, worker, max_workers=config.max_workers)

    if not all_reports:
        log.warning("No instances found across all targets.")
        sys.exit(0)

    log.info("Scan complete. %d instance report(s) collected.", len(all_reports))

    # 4. Filter if requested
    display_reports = all_reports
    if config.non_compliant_only:
        display_reports = [
            r for r in all_reports
            if r.get("overall_status") in ("NON_COMPLIANT", "NEEDS_REVIEW", "ERROR")
        ]
        log.info(
            "Filter applied: showing %d non-compliant/needs-review instance(s).",
            len(display_reports),
        )

    # 5. Generate reports
    generate_reports(
        reports=display_reports,
        output_format=config.output_format,
        output_dir=config.output_dir,
        prefix=config.report_prefix,
        detail=config.detail,
    )


if __name__ == "__main__":
    main()
