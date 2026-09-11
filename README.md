# EC2 IMDSv2 Compliance Validator — Multi-Account Edition

> **Read-only** tool. No changes are made to any AWS resource at any time.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [Installation](#4-installation)
5. [Scanning Modes](#5-scanning-modes)
6. [Usage Examples](#6-usage-examples)
7. [All CLI Options](#7-all-cli-options)
8. [Validated Scenarios](#8-validated-scenarios)
9. [Risk Assessment Logic](#9-risk-assessment-logic)
10. [Output Formats](#10-output-formats)
11. [Status Definitions](#11-status-definitions)
12. [IAM Setup for Multi-Account](#12-iam-setup-for-multi-account)
13. [Remediation Guide](#13-remediation-guide)
14. [SDK Version Reference](#14-sdk-version-reference)
15. [FAQ](#15-faq)

---

## 1. Overview

This tool scans one or more AWS accounts and regions to detect EC2 instances that are
non-compliant with the **AWS Security Hub EC2.8** control:

> *"EC2 instances should use Instance Metadata Service Version 2 (IMDSv2)"*

It evaluates **7 scenarios per instance** — not just `HttpTokens` — to surface hidden
risks that would cause a failure after enforcement (active IMDSv1 callers, EKS hop-limit
misconfiguration, stale Launch Templates, Marketplace AMI vendor agents, etc.).

It produces a **consolidated report** across all accounts and regions in a single run,
with output formats for the console, JSON, CSV, and an HTML dashboard.

---

## 2. Architecture

```
imdsv2_validator/
├── main.py                  ← Entrypoint: CLI parsing, orchestration
├── reports/                 ← Default output directory for file reports
└── modules/
    ├── __init__.py
    ├── core.py              ← Config dataclass, logging, session factory, helpers
    ├── accounts.py          ← Account discovery, role assumption, parallel runner
    ├── inspector.py         ← 7 read-only EC2 compliance checks per instance
    └── reporter.py          ← Console table, JSON, CSV, HTML report generation
```

### Module responsibilities

| Module | Responsibility |
|--------|---------------|
| `core.py` | `Config` dataclass, `setup_logging`, `base_session`, `assumed_role_session`, shared constants and helpers |
| `accounts.py` | Resolves account targets (single / explicit list / Org), assumes cross-account roles, runs workers in parallel via `ThreadPoolExecutor` |
| `inspector.py` | All 7 read-only AWS API calls per instance; builds the per-instance compliance report dict |
| `reporter.py` | Computes summary statistics, prints console table, exports JSON/CSV/HTML |
| `main.py` | Ties everything together: parses args → builds `Config` → calls `resolve_targets` → `run_parallel` → `generate_reports` |

### Data flow

```
main.py
  │
  ├─ parse_args() → build_config()
  │
  ├─ accounts.resolve_targets(config)
  │     ├─ Mode A: single account  → base_session()
  │     ├─ Mode B: explicit list   → assumed_role_session() per account
  │     └─ Mode C: AWS Orgs        → list_org_accounts() → assumed_role_session() per account
  │
  ├─ accounts.run_parallel(targets, worker=scan_target)
  │     └─ inspector.scan_target(AccountTarget)
  │           └─ _evaluate_instance() → 7 checks → returns report dict
  │
  └─ reporter.generate_reports(all_reports)
        ├─ build_summary()
        ├─ print_console_table()
        ├─ export_json()   (if requested)
        ├─ export_csv()    (if requested)
        ├─ export_html()   (if requested)
        └─ print_summary_block()
```

---

## 3. Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.8+ | |
| boto3 | 1.9.39+ | `pip install boto3` |
| tabulate | any | `pip install tabulate` — optional, improves table formatting |
| AWS credentials | — | Env vars, `~/.aws/credentials`, or attached IAM role |

---

## 4. Installation

```bash
# 1. Navigate to the project directory
cd imdsv2_validator/

# 2. Install dependencies
pip install boto3 tabulate

# 3. Verify
python3 main.py --help
```

---

## 5. Scanning Modes

The tool supports three mutually exclusive scanning modes selected at runtime.

---

### Mode A — Single Account (default)

Uses whatever credentials are active in the environment (env vars, instance profile,
`~/.aws/credentials` default profile).

```bash
python3 main.py --regions us-east-1
```

No role assumption is performed. The caller must have the required read-only
permissions directly.

---

### Mode B — Explicit Account List (`--account-ids`)

Pass a space-separated list of account IDs. The tool assumes `--role-name` in each
account using the source credentials.

```bash
python3 main.py \
  --account-ids 111122223333 444455556666 999988887777 \
  --role-name IMDSv2ValidatorRole \
  --regions us-east-1 eu-west-1
```

The source account (where you run the command) does not need to be in the list —
it will be added automatically if its credentials are the base.

---

### Mode C — AWS Organizations (`--org`)

The tool calls `organizations:ListAccounts` from the management account and
automatically builds the target list from all **ACTIVE** member accounts.

```bash
python3 main.py \
  --org \
  --role-name IMDSv2ValidatorRole \
  --regions us-east-1 us-west-2 eu-west-1 \
  --output all
```

The management account itself is also scanned (reuses the base session, no extra
role assumption).

Accounts where role assumption fails are logged and skipped — the scan continues
for all other accounts.

---

## 6. Usage Examples

```bash
# ── Single account ──────────────────────────────────────────────────────────

# Scan all instances in one region, print table
python3 main.py --regions us-east-1

# Multiple regions
python3 main.py --regions us-east-1 us-west-2 eu-west-1

# Specific instances only
python3 main.py --regions us-east-1 --instance-ids i-0abc123 i-0def456

# Only show problems, with full detail per instance
python3 main.py --regions us-east-1 --non-compliant-only --detail

# Generate all output formats (JSON + CSV + HTML written to reports/)
python3 main.py --regions us-east-1 --output all

# ── Explicit multi-account ──────────────────────────────────────────────────

python3 main.py \
  --account-ids 111122223333 444455556666 \
  --role-name IMDSv2ValidatorRole \
  --regions us-east-1 \
  --output all \
  --report-prefix "audit_q3_2026"

# ── AWS Organizations ────────────────────────────────────────────────────────

python3 main.py \
  --org \
  --role-name IMDSv2ValidatorRole \
  --regions us-east-1 us-west-2 \
  --output all \
  --output-dir /tmp/reports \
  --max-workers 10

# Use a named profile for the management account
python3 main.py \
  --org \
  --profile management-account \
  --role-name IMDSv2ValidatorRole \
  --regions us-east-1

# ── Filtering and verbosity ──────────────────────────────────────────────────

# Show only non-compliant, verbose logging
python3 main.py --regions us-east-1 --non-compliant-only --verbose

# Custom output directory and file prefix
python3 main.py --regions us-east-1 \
  --output html \
  --output-dir /var/reports/imds \
  --report-prefix "imdsv2_$(date +%Y%m%d)"
```

---

## 7. All CLI Options

```
usage: imdsv2_validator [-h] [--org | --account-ids ID [ID ...]]
                        [--regions REGION [REGION ...]]
                        [--instance-ids ID [ID ...]]
                        [--role-name ROLE] [--profile PROFILE]
                        [--output {table,json,csv,html,all}]
                        [--output-dir DIR] [--report-prefix PREFIX]
                        [--non-compliant-only] [--detail]
                        [--max-workers N] [--verbose]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--org` | off | Scan all ACTIVE accounts via AWS Organizations |
| `--account-ids` | — | Explicit account IDs (mutually exclusive with `--org`) |
| `--regions` | `us-east-1` | One or more regions to scan |
| `--instance-ids` | all | Limit scan to specific EC2 instance IDs |
| `--role-name` | `IMDSv2ValidatorRole` | IAM role name to assume in each target account |
| `--profile` | default | AWS CLI named profile for the source account |
| `--output` | `table` | Output format: `table` / `json` / `csv` / `html` / `all` |
| `--output-dir` | `reports/` | Directory for file output |
| `--report-prefix` | `imdsv2_report` | File name prefix |
| `--non-compliant-only` | off | Filter output to NON_COMPLIANT + NEEDS_REVIEW |
| `--detail` | off | Print full per-instance block to console |
| `--max-workers` | `5` | Parallel threads for account scanning |
| `--verbose` | off | Enable DEBUG logging |

---

## 8. Validated Scenarios

Seven read-only checks are performed on every EC2 instance.

---

### Check 1 — Metadata Options (Current State)

Reads `MetadataOptions` directly from `ec2:DescribeInstances`.

| Field | Compliant | Risk |
|-------|-----------|------|
| `HttpTokens` | `required` | `optional` |
| `HttpPutResponseHopLimit` | `2` for EKS, `1` for standard | `1` on EKS nodes |
| `HttpEndpoint` | `enabled` | `disabled` (no IMDS at all) |

---

### Check 2 — IMDSv1 Active Usage (CloudWatch)

Queries the `MetadataNoToken` CloudWatch metric for the past 30 days.

| `MetadataNoToken` | Meaning |
|-------------------|---------|
| `0` | No IMDSv1 calls — safe to enforce |
| `> 0` | Something is actively using IMDSv1 — identify before enforcing |
| `N/A` | Metric unavailable (stopped instance or no data published) |

Common IMDSv1 sources: old AWS CLI (< 1.16.310), old boto3 (< 1.9.39),
third-party agents (DataDog, Splunk, CrowdStrike), custom user-data scripts,
Marketplace vendor agents.

API: `cloudwatch:GetMetricStatistics`

---

### Check 3 — EKS Node Group Membership

Detects the `eks:cluster-name` tag. If present and `HopLimit < 2`, pods running
on the node cannot reach the metadata endpoint (the packet TTL drops to zero
inside the container network stack).

**Risk condition:** `is_eks_node = True AND hop_limit < 2`

Impact: Pods lose IAM credentials → AWS SDK calls fail inside containers.

---

### Check 4 — Auto Scaling Group Membership

Detects the `aws:autoscaling:groupName` tag. Patching the running instance
alone is insufficient — if the ASG's Launch Template is not updated, every new
instance will launch non-compliant.

API: `autoscaling:DescribeAutoScalingGroups`

---

### Check 5 — Launch Template Metadata Options

Reads the `MetadataOptions` block from the Launch Template version used by the
ASG (or directly from the instance if not in an ASG).

| Instance `HttpTokens` | LT `HttpTokens` | Meaning |
|----------------------|-----------------|---------|
| `required` | `required` | Fully compliant — current and future |
| `required` | `optional` | Instance patched manually — new instances still non-compliant |
| `optional` | `required` | Instance not yet patched — new instances will be OK |
| `optional` | `optional` | Fully non-compliant |

API: `ec2:DescribeLaunchTemplateVersions`

---

### Check 6 — AMI Details (Marketplace Detection)

Calls `ec2:DescribeImages` on the instance's AMI. If `ImageOwnerAlias = aws-marketplace`,
the AMI may include vendor agents or license scripts that call IMDSv1 at boot time.

Enforcing IMDSv2 before verifying vendor support can cause instances to initialize
but never complete configuration.

---

### Check 7 — Instance Context (Tags, Platform, Type)

Reads instance name tag, platform (`windows` / `linux`), instance type, AZ, and
launch time. Used to enrich all other checks with context for the final report.

---

## 9. Risk Assessment Logic

```
Is HttpTokens == required?
├── NO  → NON_COMPLIANT
│         All applicable risk flags are collected
└── YES → Any additional risk flags?
          ├── NO  → COMPLIANT
          └── YES → NEEDS_REVIEW
                    (enforced but secondary risks exist)
```

### Risk flags and severity

| Risk | Condition | Severity |
|------|-----------|----------|
| IMDSv2 not enforced | `HttpTokens != required` | HIGH |
| Active IMDSv1 callers | `MetadataNoToken > 0` | HIGH |
| EKS hop-limit risk | `is_eks_node AND hop_limit < 2` | HIGH |
| Launch Template not updated | `lt_http_tokens != required` | MEDIUM |
| Marketplace AMI | `ami_owner_alias == aws-marketplace` | MEDIUM |
| Metadata endpoint disabled | `HttpEndpoint == disabled` | INFO |

---

## 10. Output Formats

### Console table (`--output table`)

Grid table with one row per instance. Columns include account, region,
`HttpTokens`, hop limit, EKS, ASG, Launch Template tokens, Marketplace flag,
IMDSv1 calls, and status.

### Per-instance detail (`--detail`)

Full block for every instance showing all 7 check results, risk list,
and actionable recommendations.

### JSON (`--output json`)

Structured file at `reports/imdsv2_report.json`:

```json
{
  "summary": {
    "generated_at": "2026-07-31 22:00:00 UTC",
    "total_instances": 42,
    "compliant": 30,
    "needs_review": 7,
    "non_compliant": 5,
    "compliance_pct": 71.4,
    "eks_hop_risk": 3,
    "lt_not_updated": 4,
    "marketplace_amis": 2,
    "imdsv1_active_callers": 6,
    "accounts_scanned": 3,
    "regions_scanned": 2,
    "account_ids": ["111122223333", "444455556666", "999988887777"],
    "regions": ["us-east-1", "us-west-2"]
  },
  "instances": [ ... ]
}
```

### CSV (`--output csv`)

Flat file at `reports/imdsv2_report.csv` with all scalar fields plus
`risks_summary` and `recommendations_summary` columns (pipe-separated).

### HTML (`--output html`)

Standalone dashboard at `reports/imdsv2_report.html` with:
- 8-card summary grid (totals, compliance %, risk counts)
- Full sortable instance table with color-coded status
- Metadata footer listing every API call made

### All formats (`--output all`)

Writes JSON + CSV + HTML simultaneously. Console table is also printed.

---

## 11. Status Definitions

| Status | Meaning |
|--------|---------|
| `COMPLIANT` | `HttpTokens=required` and no secondary risk flags |
| `NEEDS_REVIEW` | `HttpTokens=required` but at least one risk flag exists |
| `NON_COMPLIANT` | `HttpTokens=optional` — IMDSv2 is not enforced |
| `ERROR` | Account or scan-level failure (role assumption error, API error) |

---

## 12. IAM Setup for Multi-Account

### Management / source account

The account where you run `main.py` needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IMDSv2ValidatorSource",
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole",
        "sts:GetCallerIdentity",
        "organizations:ListAccounts",
        "organizations:DescribeOrganization"
      ],
      "Resource": "*"
    }
  ]
}
```

> `organizations:*` is only required for `--org` mode.

---

### Target account role (`IMDSv2ValidatorRole`)

Create this role in **every account you want to scan**. It needs only read-only
EC2 and CloudWatch permissions.

**Trust policy** — allows the management account to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "IMDSv2Validator"
        }
      }
    }
  ]
}
```

> Replace `MANAGEMENT_ACCOUNT_ID` with your actual management account ID.
> The `ExternalId` condition is recommended to prevent confused-deputy attacks.

**Permissions policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IMDSv2ValidatorReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
        "ec2:DescribeLaunchTemplateVersions",
        "autoscaling:DescribeAutoScalingGroups",
        "cloudwatch:GetMetricStatistics",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

### Deploy the role via AWS CLI (repeat per target account)

```bash
TARGET_ACCOUNT="444455556666"
MGMT_ACCOUNT="111122223333"

# Create role
aws iam create-role \
  --role-name IMDSv2ValidatorRole \
  --assume-role-policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Principal\": {\"AWS\": \"arn:aws:iam::${MGMT_ACCOUNT}:root\"},
      \"Action\": \"sts:AssumeRole\"
    }]
  }" \
  --profile target-account-profile

# Attach read-only policy
aws iam put-role-policy \
  --role-name IMDSv2ValidatorRole \
  --policy-name IMDSv2ValidatorPolicy \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeImages",
        "ec2:DescribeLaunchTemplateVersions",
        "autoscaling:DescribeAutoScalingGroups",
        "cloudwatch:GetMetricStatistics",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }]
  }' \
  --profile target-account-profile
```

### Deploy across all Org accounts via CloudFormation StackSet

For large Organizations, use a CloudFormation StackSet to deploy the role to
all member accounts automatically. See the AWS documentation:
https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html

---

## 13. Remediation Guide

> The script does NOT perform any of the following steps.
> These are manual actions to take after identifying non-compliant instances.

### Step 1 — Identify IMDSv1 callers (if `MetadataNoToken > 0`)

SSH into the instance:

```bash
# Check cloud-init and boot logs
sudo grep -r "169.254.169.254" /var/log/cloud-init*.log
sudo grep -r "169.254.169.254" /var/log/user-data.log 2>/dev/null

# Search scripts and agents
sudo grep -rn "169.254.169.254" /etc/init.d/ /opt/ /usr/local/ 2>/dev/null

# Check SDK versions
aws --version
pip3 show boto3 | grep Version
```

### Step 2 — Fix EKS nodes (hop limit first)

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxxx \
  --http-tokens required \
  --http-put-response-hop-limit 2 \
  --http-endpoint enabled \
  --region us-east-1
```

### Step 3 — Enforce IMDSv2 on standard instances

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-xxxxxxxxx \
  --http-tokens required \
  --http-put-response-hop-limit 1 \
  --http-endpoint enabled \
  --region us-east-1
```

### Step 4 — Update the Launch Template (ASG instances)

```bash
aws ec2 create-launch-template-version \
  --launch-template-id lt-xxxxxxxxx \
  --source-version '$Latest' \
  --launch-template-data '{
    "MetadataOptions": {
      "HttpTokens": "required",
      "HttpPutResponseHopLimit": 2,
      "HttpEndpoint": "enabled"
    }
  }'

aws ec2 modify-launch-template \
  --launch-template-id lt-xxxxxxxxx \
  --default-version '$Latest'
```

### Step 5 — Prevent non-compliant launches (SCP)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "ec2:RunInstances",
    "Resource": "arn:aws:ec2:*:*:instance/*",
    "Condition": {
      "StringNotEquals": {
        "ec2:MetadataHttpTokens": "required"
      }
    }
  }]
}
```

### Step 6 — Verify

```bash
aws ec2 describe-instances \
  --instance-id i-xxxxxxxxx \
  --query "Reservations[].Instances[].MetadataOptions" \
  --output table
```

Expected: `HttpTokens: required`

---

## 14. SDK Version Reference

Minimum versions that support IMDSv2 session-oriented requests:

| SDK / Tool | Minimum Version |
|------------|----------------|
| AWS CLI v1 | 1.16.310 |
| AWS CLI v2 | any |
| boto3 (Python) | 1.9.39 |
| AWS SDK for Java v1 | 1.11.678 |
| AWS SDK for Java v2 | 2.13.1 |
| AWS SDK for JavaScript v2 | 2.814.0 |
| AWS SDK for Go v1 | 1.34.0 |
| AWS SDK for Ruby | 3.x (all) |
| AWS SDK for .NET | 3.7.x (all) |

---

## 15. FAQ

**Q: Does this tool make any changes to my infrastructure?**  
No. Every AWS API call is a `Describe*`, `Get*`, `List*`, or `GetCallerIdentity`. No
`Modify*`, `Create*`, `Delete*`, or `Put*` calls are made to EC2, ASG, or any other
resource.

**Q: What happens if role assumption fails for one account?**  
That account is logged as a warning, skipped, and an ERROR row is included in the
final report. All other accounts continue scanning normally.

**Q: Can I scan multiple regions at once?**  
Yes. Pass all regions with `--regions`:
```bash
python3 main.py --regions us-east-1 us-west-2 eu-west-1 ap-southeast-1
```
Each account × region combination becomes a parallel work unit.

**Q: Why does a COMPLIANT instance show up as NEEDS_REVIEW?**  
`HttpTokens=required` is enforced on the running instance, but at least one
secondary risk exists — for example, the Launch Template has not been updated
(new ASG instances will be non-compliant), or active IMDSv1 calls were detected
(a process may break if the change was recent).

**Q: Why is MetadataNoToken shown as N/A?**  
The CloudWatch metric is not published for stopped instances, very recently launched
instances, or instances where the metric has aged out of the retention window. It does
not confirm IMDSv1 callers are present.

**Q: My EKS node shows NEEDS_REVIEW even with HttpTokens=required. Why?**  
The hop limit is `1`. With `HopLimit=1` on an EKS node, containers cannot reach the
metadata endpoint. Set `HttpPutResponseHopLimit=2` to resolve this.

**Q: Can I use this in a CI/CD or automation pipeline?**  
Yes. Use `--output json` or `--output csv`. The tool exits with code `0` on success
regardless of compliance status — it is a reporting tool, not a gate. Wrap it in your
own gate logic if needed.

**Q: How do I deploy `IMDSv2ValidatorRole` across 50+ accounts quickly?**  
Use AWS CloudFormation StackSets with service-managed permissions. This deploys the
role to all current and future member accounts automatically. See
[Section 12](#12-iam-setup-for-multi-account) for the role definition.

---

*Version: 2.0 — Modular, multi-account, read-only.*  
*All AWS resources are unmodified during any scan.*
