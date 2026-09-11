"""
modules/reporter.py
-------------------
Consolidated report generation from multi-account scan results.

Supported output formats
------------------------
- table : Console grid table (requires tabulate)
- json  : Structured JSON file
- csv   : Flat CSV file for spreadsheet analysis
- html  : Standalone HTML report with summary dashboard
- all   : Produces json + csv + html simultaneously
"""

import csv
import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

log = logging.getLogger("imdsv2_validator.reporter")

try:
    from tabulate import tabulate
    _TABULATE = True
except ImportError:
    _TABULATE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt(value: bool) -> str:
    return "YES" if value else "NO"


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def build_summary(reports: List[dict]) -> dict:
    """Compute aggregate statistics across all reports."""
    total = len(reports)
    compliant = sum(1 for r in reports if r.get("overall_status") == "COMPLIANT")
    needs_review = sum(1 for r in reports if r.get("overall_status") == "NEEDS_REVIEW")
    non_compliant = sum(1 for r in reports if r.get("overall_status") == "NON_COMPLIANT")
    error = sum(1 for r in reports if r.get("overall_status") == "ERROR")
    eks_risk = sum(1 for r in reports if r.get("eks_hop_risk"))
    lt_risk = sum(1 for r in reports if r.get("lt_compliant") is False)
    marketplace = sum(1 for r in reports if r.get("ami_is_marketplace"))
    imdsv1_active = sum(1 for r in reports if r.get("imdsv1_active"))

    accounts = sorted({r.get("account_id", "") for r in reports})
    regions = sorted({r.get("region", "") for r in reports})

    return {
        "generated_at": _ts(),
        "total_instances": total,
        "compliant": compliant,
        "needs_review": needs_review,
        "non_compliant": non_compliant,
        "error": error,
        "compliance_pct": round((compliant / total * 100), 1) if total else 0.0,
        "eks_hop_risk": eks_risk,
        "lt_not_updated": lt_risk,
        "marketplace_amis": marketplace,
        "imdsv1_active_callers": imdsv1_active,
        "accounts_scanned": len(accounts),
        "regions_scanned": len(regions),
        "account_ids": accounts,
        "regions": regions,
    }


# ---------------------------------------------------------------------------
# Console table
# ---------------------------------------------------------------------------

def print_console_table(reports: List[dict], detail: bool = False):
    """Print summary table to stdout."""
    if not reports:
        print("[INFO] No instances to display.")
        return

    headers = [
        "Account", "Region", "Instance ID", "Name",
        "HttpTokens", "HL", "EKS", "EKS Risk",
        "ASG", "LT Tokens", "Mktpl", "IMDSv1(30d)", "Status"
    ]

    rows = []
    for r in reports:
        rows.append([
            r.get("account_id", "")[-6:],          # last 6 digits of account ID
            r.get("region", ""),
            r.get("instance_id", ""),
            (r.get("name") or "")[:20],
            r.get("http_tokens", ""),
            r.get("hop_limit", ""),
            _fmt(r.get("is_eks_node", False)),
            _fmt(r.get("eks_hop_risk", False)),
            _fmt(r.get("is_asg", False)),
            r.get("lt_http_tokens", "n/a"),
            _fmt(r.get("ami_is_marketplace", False)),
            r.get("imdsv1_calls_30d") if r.get("imdsv1_calls_30d") is not None else "N/A",
            r.get("overall_status", ""),
        ])

    if _TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    else:
        print("  ".join(headers))
        for row in rows:
            print("  ".join(str(c) for c in row))

    if detail:
        for r in reports:
            _print_instance_detail(r)


def _print_instance_detail(r: dict):
    sep = "-" * 65
    print(f"\n{sep}")
    print(f"  Account  : {r.get('account_id')} ({r.get('account_name')})")
    print(f"  Region   : {r.get('region')}  |  AZ: {r.get('az')}")
    print(f"  Instance : {r.get('instance_id')}  ({r.get('name')})")
    print(f"  Type     : {r.get('instance_type')}  |  Platform: {r.get('platform')}")
    print(f"  State    : {r.get('state')}  |  Launched: {r.get('launch_time')}")
    print(f"\n  [ METADATA OPTIONS ]")
    print(f"    HttpTokens   : {r.get('http_tokens')}")
    print(f"    HopLimit     : {r.get('hop_limit')}")
    print(f"    HttpEndpoint : {r.get('http_endpoint')}")
    print(f"    IMDSv2 Enforced : {_fmt(r.get('imdsv2_enforced', False))}")
    print(f"\n  [ EKS ]  Node: {_fmt(r.get('is_eks_node', False))}  |  "
          f"Cluster: {r.get('eks_cluster') or 'n/a'}  |  "
          f"HopRisk: {_fmt(r.get('eks_hop_risk', False))}")
    print(f"\n  [ ASG / LAUNCH TEMPLATE ]")
    print(f"    In ASG         : {_fmt(r.get('is_asg', False))}")
    if r.get("is_asg"):
        print(f"    ASG Name       : {r.get('asg_name')}")
        print(f"    LT ID          : {r.get('lt_id')}")
        print(f"    LT HttpTokens  : {r.get('lt_http_tokens')}")
        lt_c = r.get("lt_compliant")
        print(f"    LT Compliant   : {_fmt(lt_c) if lt_c is not None else 'N/A'}")
    print(f"\n  [ AMI ]  {r.get('ami_id')}  |  {r.get('ami_name')}  |  "
          f"Marketplace: {_fmt(r.get('ami_is_marketplace', False))}")
    print(f"\n  [ IMDSv1 USAGE — last 30 days ]")
    calls = r.get("imdsv1_calls_30d")
    print(f"    MetadataNoToken : {calls if calls is not None else 'N/A'}")
    print(f"    Active IMDSv1   : {_fmt(r.get('imdsv1_active', False))}")
    print(f"\n  [ ASSESSMENT ]  Status: {r.get('overall_status')}")
    for risk in r.get("risks", []):
        print(f"    ⚠  {risk}")
    for rec in r.get("recommendations", []):
        print(f"    →  {rec}")
    print(sep)


def print_summary_block(summary: dict):
    """Print the final summary statistics block to stdout."""
    print("\n" + "=" * 65)
    print("  IMDSv2 COMPLIANCE — FINAL CONSOLIDATED REPORT")
    print("=" * 65)
    print(f"  Generated        : {summary['generated_at']}")
    print(f"  Accounts scanned : {summary['accounts_scanned']}  "
          f"({', '.join(summary['account_ids'])})")
    print(f"  Regions scanned  : {summary['regions_scanned']}  "
          f"({', '.join(summary['regions'])})")
    print(f"  ─────────────────────────────────────────────")
    print(f"  Total instances  : {summary['total_instances']}")
    print(f"  ✓ COMPLIANT      : {summary['compliant']}  "
          f"({summary['compliance_pct']}%)")
    print(f"  ⚠ NEEDS REVIEW   : {summary['needs_review']}")
    print(f"  ✗ NON-COMPLIANT  : {summary['non_compliant']}")
    if summary["error"]:
        print(f"  ! ERRORS         : {summary['error']}")
    print(f"  ─────────────────────────────────────────────")
    print(f"  Active IMDSv1 callers    : {summary['imdsv1_active_callers']}")
    print(f"  EKS hop-limit risk       : {summary['eks_hop_risk']}")
    print(f"  Launch Template not fixed: {summary['lt_not_updated']}")
    print(f"  Marketplace AMIs flagged : {summary['marketplace_amis']}")
    print("=" * 65)
    print("  All operations were READ-ONLY. No changes were made.")
    print("=" * 65 + "\n")


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_json(reports: List[dict], summary: dict, path: str):
    _ensure_dir(os.path.dirname(path))
    payload = {"summary": summary, "instances": reports}
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    log.info("JSON report saved → %s", path)
    print(f"[INFO] JSON report   → {path}")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

_CSV_SCALAR_FIELDS = [
    "account_id", "account_name", "region", "instance_id", "name",
    "state", "instance_type", "az", "platform", "launch_time",
    "http_tokens", "hop_limit", "http_endpoint", "imdsv2_enforced",
    "is_eks_node", "eks_cluster", "eks_hop_risk",
    "is_asg", "asg_name", "lt_id", "lt_http_tokens", "lt_compliant",
    "ami_id", "ami_name", "ami_is_marketplace", "ami_owner_alias",
    "imdsv1_calls_30d", "imdsv1_active",
    "overall_status",
]

def export_csv(reports: List[dict], path: str):
    _ensure_dir(os.path.dirname(path))
    fieldnames = _CSV_SCALAR_FIELDS + ["risks_summary", "recommendations_summary"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in reports:
            row = {k: r.get(k, "") for k in _CSV_SCALAR_FIELDS}
            row["risks_summary"] = " | ".join(r.get("risks", []))
            row["recommendations_summary"] = " | ".join(r.get("recommendations", []))
            writer.writerow(row)
    log.info("CSV report saved → %s", path)
    print(f"[INFO] CSV report    → {path}")


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

_STATUS_COLOR = {
    "COMPLIANT": "#28a745",
    "NEEDS_REVIEW": "#fd7e14",
    "NON_COMPLIANT": "#dc3545",
    "ERROR": "#6c757d",
}

def export_html(reports: List[dict], summary: dict, path: str):
    _ensure_dir(os.path.dirname(path))

    rows_html = ""
    for r in reports:
        status = r.get("overall_status", "")
        color = _STATUS_COLOR.get(status, "#333")
        risks_html = "<br>".join(r.get("risks", []))
        recs_html = "<br>".join(r.get("recommendations", []))
        rows_html += f"""
        <tr>
          <td>{r.get('account_id','')}</td>
          <td>{r.get('region','')}</td>
          <td>{r.get('instance_id','')}</td>
          <td>{r.get('name','')}</td>
          <td>{r.get('state','')}</td>
          <td>{r.get('http_tokens','')}</td>
          <td>{r.get('hop_limit','')}</td>
          <td>{'YES' if r.get('is_eks_node') else 'NO'}</td>
          <td>{'YES' if r.get('eks_hop_risk') else 'NO'}</td>
          <td>{'YES' if r.get('is_asg') else 'NO'}</td>
          <td>{r.get('lt_http_tokens','n/a')}</td>
          <td>{'YES' if r.get('ami_is_marketplace') else 'NO'}</td>
          <td>{r.get('imdsv1_calls_30d') if r.get('imdsv1_calls_30d') is not None else 'N/A'}</td>
          <td style="color:{color};font-weight:bold">{status}</td>
          <td>{risks_html}</td>
          <td>{recs_html}</td>
        </tr>"""

    accts_str = ", ".join(summary.get("account_ids", []))
    regions_str = ", ".join(summary.get("regions", []))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IMDSv2 Compliance Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; color: #333; }}
    h1 {{ color: #232f3e; }}
    .summary-grid {{
      display: grid; grid-template-columns: repeat(4, 1fr);
      gap: 16px; margin: 24px 0;
    }}
    .card {{
      background: #fff; border-radius: 8px;
      padding: 20px; box-shadow: 0 2px 6px rgba(0,0,0,.1);
      text-align: center;
    }}
    .card .value {{ font-size: 2.2em; font-weight: bold; margin: 8px 0; }}
    .card .label {{ font-size: 0.9em; color: #666; }}
    .compliant {{ color: #28a745; }}
    .review    {{ color: #fd7e14; }}
    .noncompliant {{ color: #dc3545; }}
    .neutral   {{ color: #232f3e; }}
    table {{
      width: 100%; border-collapse: collapse;
      background: #fff; border-radius: 8px;
      overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,.1);
    }}
    th {{
      background: #232f3e; color: #fff;
      padding: 10px 8px; text-align: left; font-size: 0.82em;
    }}
    td {{ padding: 8px; border-bottom: 1px solid #e9ecef; font-size: 0.82em; }}
    tr:hover {{ background: #f1f3f5; }}
    .meta {{ color: #666; font-size: 0.85em; margin-bottom: 20px; }}
    .badge-readonly {{
      background: #232f3e; color: #fff;
      padding: 4px 10px; border-radius: 4px; font-size: 0.8em;
    }}
  </style>
</head>
<body>
  <h1>&#128274; EC2 IMDSv2 Compliance Report</h1>
  <p class="meta">
    Generated: <strong>{summary['generated_at']}</strong> &nbsp;|&nbsp;
    Accounts: <strong>{accts_str}</strong> &nbsp;|&nbsp;
    Regions: <strong>{regions_str}</strong> &nbsp;|&nbsp;
    <span class="badge-readonly">READ-ONLY — No changes made</span>
  </p>

  <div class="summary-grid">
    <div class="card">
      <div class="label">Total Instances</div>
      <div class="value neutral">{summary['total_instances']}</div>
    </div>
    <div class="card">
      <div class="label">Compliant</div>
      <div class="value compliant">{summary['compliant']}</div>
      <div class="label">{summary['compliance_pct']}%</div>
    </div>
    <div class="card">
      <div class="label">Needs Review</div>
      <div class="value review">{summary['needs_review']}</div>
    </div>
    <div class="card">
      <div class="label">Non-Compliant</div>
      <div class="value noncompliant">{summary['non_compliant']}</div>
    </div>
    <div class="card">
      <div class="label">Active IMDSv1 Callers</div>
      <div class="value noncompliant">{summary['imdsv1_active_callers']}</div>
    </div>
    <div class="card">
      <div class="label">EKS Hop-Limit Risk</div>
      <div class="value review">{summary['eks_hop_risk']}</div>
    </div>
    <div class="card">
      <div class="label">Launch Template Not Updated</div>
      <div class="value review">{summary['lt_not_updated']}</div>
    </div>
    <div class="card">
      <div class="label">Marketplace AMIs</div>
      <div class="value neutral">{summary['marketplace_amis']}</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Account ID</th><th>Region</th><th>Instance ID</th><th>Name</th>
        <th>State</th><th>HttpTokens</th><th>HopLimit</th>
        <th>EKS Node</th><th>EKS Risk</th><th>In ASG</th>
        <th>LT HttpTokens</th><th>Marketplace</th>
        <th>IMDSv1(30d)</th><th>Status</th>
        <th>Risks</th><th>Recommendations</th>
      </tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>

  <p class="meta" style="margin-top:20px">
    All API calls in this report were read-only:<br>
    ec2:DescribeInstances &bull; ec2:DescribeImages &bull;
    ec2:DescribeLaunchTemplateVersions &bull;
    autoscaling:DescribeAutoScalingGroups &bull;
    cloudwatch:GetMetricStatistics &bull;
    organizations:ListAccounts &bull; sts:GetCallerIdentity
  </p>
</body>
</html>"""

    with open(path, "w") as fh:
        fh.write(html)
    log.info("HTML report saved → %s", path)
    print(f"[INFO] HTML report   → {path}")


# ---------------------------------------------------------------------------
# Public orchestrator
# ---------------------------------------------------------------------------

def generate_reports(
    reports: List[dict],
    output_format: str,
    output_dir: str,
    prefix: str,
    detail: bool = False,
):
    """
    Generate all requested output formats.

    Parameters
    ----------
    reports       : List of per-instance compliance dicts from inspector.
    output_format : 'table' | 'json' | 'csv' | 'html' | 'all'
    output_dir    : Directory to write file reports into.
    prefix        : File name prefix.
    detail        : Print per-instance detail blocks to console.
    """
    summary = build_summary(reports)

    json_path = os.path.join(output_dir, f"{prefix}.json")
    csv_path = os.path.join(output_dir, f"{prefix}.csv")
    html_path = os.path.join(output_dir, f"{prefix}.html")

    if output_format in ("table", "all"):
        print_console_table(reports, detail=detail)

    if output_format in ("json", "all"):
        export_json(reports, summary, json_path)

    if output_format in ("csv", "all"):
        export_csv(reports, csv_path)

    if output_format in ("html", "all"):
        export_html(reports, summary, html_path)

    print_summary_block(summary)
    return summary
