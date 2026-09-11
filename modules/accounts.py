"""
modules/accounts.py
-------------------
Account discovery and session management for multi-account / AWS Organizations
environments.

Supported modes
---------------
1. Single account   — uses the default credential chain (no extra config).
2. Explicit list    — caller passes a list of account IDs; the tool assumes
                      a named role in each one.
3. AWS Organizations— the tool lists all ACTIVE accounts in the Org
                      (using the management account credentials) and assumes
                      a named role in each member account.

All operations in this module are READ-ONLY.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional

import boto3
from botocore.exceptions import ClientError

from .core import (
    Config,
    assumed_role_session,
    base_session,
    tag_value,
    validate_credentials,
)

log = logging.getLogger("imdsv2_validator.accounts")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class AccountTarget:
    """Represents one AWS account + region combination to be scanned."""
    account_id: str
    account_name: str
    region: str
    session: boto3.Session
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Organization account discovery
# ---------------------------------------------------------------------------

def list_org_accounts(mgmt_session: boto3.Session) -> List[Dict]:
    """
    List all ACTIVE accounts in the AWS Organization.
    Must be called from the management (payer) account or a delegated admin.

    Returns a list of dicts: {Id, Name, Email, Status}
    """
    org = mgmt_session.client("organizations", region_name="us-east-1")
    accounts = []
    try:
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page.get("Accounts", []):
                if acct.get("Status") == "ACTIVE":
                    accounts.append(acct)
        log.info("Discovered %d active accounts in the Organization.", len(accounts))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
            log.error(
                "Cannot list Org accounts (%s). Ensure you are running from the "
                "management account or a delegated admin with organizations:ListAccounts.",
                code,
            )
        else:
            log.error("list_accounts failed: %s", exc)
        raise
    return accounts


def get_management_account_id(mgmt_session: boto3.Session) -> str:
    """Return the management account ID for the Organization."""
    org = mgmt_session.client("organizations", region_name="us-east-1")
    try:
        resp = org.describe_organization()
        return resp["Organization"]["MasterAccountId"]
    except ClientError as exc:
        log.warning("Could not describe organization: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Session builder per account
# ---------------------------------------------------------------------------

def _build_session_for_account(
    account: Dict,
    role_name: str,
    region: str,
    mgmt_session: boto3.Session,
    mgmt_account_id: str,
) -> AccountTarget:
    """
    Assume the cross-account role in *account* and return an AccountTarget.
    If the account is the management account itself, reuse the mgmt session.
    """
    account_id = account["Id"]
    account_name = account.get("Name", account_id)

    # Management account — no need to assume role
    if account_id == mgmt_account_id:
        log.debug("Using existing session for management account %s.", account_id)
        return AccountTarget(
            account_id=account_id,
            account_name=account_name,
            region=region,
            session=mgmt_session,
        )

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    log.debug("Assuming %s for account %s (%s).", role_arn, account_id, account_name)
    try:
        session = assumed_role_session(
            role_arn=role_arn,
            session_name="IMDSv2Validator",
            base=mgmt_session,
            region=region,
        )
        return AccountTarget(
            account_id=account_id,
            account_name=account_name,
            region=region,
            session=session,
        )
    except RuntimeError as exc:
        log.warning("Skipping account %s (%s): %s", account_id, account_name, exc)
        return AccountTarget(
            account_id=account_id,
            account_name=account_name,
            region=region,
            session=None,
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Public: resolve all AccountTarget objects based on Config
# ---------------------------------------------------------------------------

def resolve_targets(config: Config) -> List[AccountTarget]:
    """
    Return the full list of (account, region) targets to scan, based on
    the configuration:

    - use_org=True  → discover all accounts via Organizations
    - account_ids   → explicit list, assume role in each
    - neither       → single account using default credentials
    """
    mgmt_session = base_session(
        profile=config.management_profile,
        region=config.regions[0] if config.regions else "us-east-1",
    )
    validate_credentials(mgmt_session, log)

    targets: List[AccountTarget] = []

    # ── Mode 1: AWS Organizations ──────────────────────────────────────────
    if config.use_org:
        log.info("Mode: AWS Organizations — discovering member accounts.")
        mgmt_account_id = get_management_account_id(mgmt_session)
        try:
            org_accounts = list_org_accounts(mgmt_session)
        except ClientError:
            log.error("Failed to list organization accounts. Aborting.")
            return []

        for region in config.regions:
            for acct in org_accounts:
                target = _build_session_for_account(
                    account=acct,
                    role_name=config.org_role_name,
                    region=region,
                    mgmt_session=mgmt_session,
                    mgmt_account_id=mgmt_account_id,
                )
                targets.append(target)

    # ── Mode 2: Explicit account list ─────────────────────────────────────
    elif config.account_ids:
        log.info("Mode: Explicit account list (%d accounts).", len(config.account_ids))
        mgmt_account_id = ""
        try:
            sts = mgmt_session.client("sts")
            mgmt_account_id = sts.get_caller_identity()["Account"]
        except ClientError:
            pass

        for region in config.regions:
            for account_id in config.account_ids:
                acct = {"Id": account_id, "Name": account_id}
                target = _build_session_for_account(
                    account=acct,
                    role_name=config.org_role_name,
                    region=region,
                    mgmt_session=mgmt_session,
                    mgmt_account_id=mgmt_account_id,
                )
                targets.append(target)

    # ── Mode 3: Single account (default credentials) ──────────────────────
    else:
        log.info("Mode: Single account (default credentials).")
        sts = mgmt_session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        for region in config.regions:
            sess = base_session(profile=config.management_profile, region=region)
            targets.append(AccountTarget(
                account_id=account_id,
                account_name=account_id,
                region=region,
                session=sess,
            ))

    valid = [t for t in targets if t.error is None]
    failed = [t for t in targets if t.error is not None]
    log.info(
        "Targets resolved: %d valid, %d failed (role assumption errors).",
        len(valid), len(failed),
    )
    return targets


# ---------------------------------------------------------------------------
# Parallel execution helper
# ---------------------------------------------------------------------------

def run_parallel(
    targets: List[AccountTarget],
    worker_fn: Callable[[AccountTarget], list],
    max_workers: int = 5,
) -> List[dict]:
    """
    Execute *worker_fn* for each target in parallel.
    Each worker_fn receives an AccountTarget and returns a list of result dicts.
    Results are flattened into a single list.
    """
    all_results = []
    failed_targets = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(worker_fn, target): target
            for target in targets
            if target.error is None
        }
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results = future.result()
                all_results.extend(results)
                log.info(
                    "Account %s / %s — %d instance(s) evaluated.",
                    target.account_id, target.region, len(results),
                )
            except Exception as exc:  # noqa: BLE001
                log.error(
                    "Worker failed for account %s / %s: %s",
                    target.account_id, target.region, exc,
                )
                failed_targets.append({
                    "account_id": target.account_id,
                    "account_name": target.account_name,
                    "region": target.region,
                    "error": str(exc),
                })

    # Attach failed account entries (no instances but error recorded)
    for ft in failed_targets:
        all_results.append({
            **ft,
            "instance_id": "N/A",
            "overall_status": "ERROR",
            "risks": [ft["error"]],
            "recommendations": [],
        })

    return all_results
