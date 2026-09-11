"""
modules/inspector.py
--------------------
Read-only EC2 IMDSv2 compliance checks.

For each EC2 instance this module evaluates:
  1. Metadata options (HttpTokens, HopLimit, HttpEndpoint)
  2. IMDSv1 active usage via CloudWatch MetadataNoToken
  3. EKS node membership and hop-limit risk
  4. Auto Scaling Group membership
  5. Launch Template metadata compliance
  6. AMI details (Marketplace / custom image detection)
  7. Platform, tags, and instance context

No write or modify operations are performed.
"""

import logging
from datetime import timedelta
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from .core import (
    ASG_TAG_KEY,
    EKS_TAG_KEY,
    IMDSV1_METRIC,
    LOOKBACK_DAYS,
    MARKETPLACE_OWNER_ALIAS,
    METRIC_NAMESPACE,
    now_utc,
    safe_get,
    tag_value,
)
from .accounts import AccountTarget

log = logging.getLogger("imdsv2_validator.inspector")


# ---------------------------------------------------------------------------
# Low-level AWS fetchers
# ---------------------------------------------------------------------------

class _AWSClients:
    """Thin wrapper to build regional clients from a boto3 session."""

    def __init__(self, session: boto3.Session, region: str):
        self.ec2 = session.client("ec2", region_name=region)
        self.cw = session.client("cloudwatch", region_name=region)
        self.asg = session.client("autoscaling", region_name=region)


def _list_instances(clients: _AWSClients, instance_ids: List[str]) -> List[dict]:
    """Return EC2 instances (running / stopped / pending)."""
    filters = [{"Name": "instance-state-name", "Values": ["running", "stopped", "pending"]}]
    paginator = clients.ec2.get_paginator("describe_instances")
    kwargs: dict = {}
    if instance_ids:
        kwargs["InstanceIds"] = instance_ids
    else:
        kwargs["Filters"] = filters

    instances = []
    try:
        for page in paginator.paginate(**kwargs):
            for res in page.get("Reservations", []):
                instances.extend(res.get("Instances", []))
    except ClientError as exc:
        log.error("describe_instances failed: %s", exc)
    return instances


def _get_imdsv1_usage(clients: _AWSClients, instance_id: str) -> dict:
    """Query CloudWatch MetadataNoToken metric for last LOOKBACK_DAYS days."""
    end = now_utc()
    start = end - timedelta(days=LOOKBACK_DAYS)
    result = {"total_imdsv1_calls": None, "error": None}
    try:
        resp = clients.cw.get_metric_statistics(
            Namespace=METRIC_NAMESPACE,
            MetricName=IMDSV1_METRIC,
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=end,
            Period=LOOKBACK_DAYS * 86400,
            Statistics=["Sum"],
        )
        datapoints = resp.get("Datapoints", [])
        result["total_imdsv1_calls"] = int(sum(dp["Sum"] for dp in datapoints)) if datapoints else 0
    except ClientError as exc:
        result["error"] = str(exc)
    return result


def _get_ami_details(clients: _AWSClients, ami_id: str) -> dict:
    """Return AMI name, owner, and marketplace flag."""
    result = {
        "ami_id": ami_id, "name": "unknown", "description": "",
        "owner_id": "", "owner_alias": "",
        "is_marketplace": False, "error": None,
    }
    try:
        resp = clients.ec2.describe_images(ImageIds=[ami_id])
        images = resp.get("Images", [])
        if not images:
            result["error"] = "AMI not found (may be deregistered)"
            return result
        img = images[0]
        result.update({
            "name": img.get("Name", ""),
            "description": img.get("Description", ""),
            "owner_id": img.get("OwnerId", ""),
            "owner_alias": img.get("ImageOwnerAlias", ""),
            "is_marketplace": img.get("ImageOwnerAlias", "") == MARKETPLACE_OWNER_ALIAS,
        })
    except ClientError as exc:
        result["error"] = str(exc)
    return result


def _get_launch_template_metadata(
    clients: _AWSClients, lt_id: str, lt_version: str
) -> dict:
    """Return MetadataOptions from a Launch Template version."""
    result = {
        "lt_id": lt_id, "lt_version": lt_version,
        "http_tokens": None, "hop_limit": None,
        "http_endpoint": None, "error": None,
    }
    try:
        resp = clients.ec2.describe_launch_template_versions(
            LaunchTemplateId=lt_id,
            Versions=[str(lt_version)],
        )
        versions = resp.get("LaunchTemplateVersions", [])
        if not versions:
            result["error"] = "Launch template version not found"
            return result
        meta = versions[0].get("LaunchTemplateData", {}).get("MetadataOptions", {})
        result.update({
            "http_tokens": meta.get("HttpTokens", "not-set"),
            "hop_limit": meta.get("HttpPutResponseHopLimit", "not-set"),
            "http_endpoint": meta.get("HttpEndpoint", "not-set"),
        })
    except ClientError as exc:
        result["error"] = str(exc)
    return result


def _get_asg_launch_template(clients: _AWSClients, asg_name: str) -> dict:
    """Return the Launch Template ID and version used by an ASG."""
    result = {"lt_id": None, "lt_version": None, "error": None}
    try:
        resp = clients.asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        groups = resp.get("AutoScalingGroups", [])
        if not groups:
            result["error"] = "ASG not found"
            return result
        group = groups[0]
        lt = group.get("LaunchTemplate")
        if lt:
            result["lt_id"] = lt.get("LaunchTemplateId")
            result["lt_version"] = lt.get("Version", "$Default")
        else:
            mip_lt = safe_get(
                group, "MixedInstancesPolicy",
                "LaunchTemplate", "LaunchTemplateSpecification"
            )
            if mip_lt:
                result["lt_id"] = mip_lt.get("LaunchTemplateId")
                result["lt_version"] = mip_lt.get("Version", "$Default")
            else:
                result["error"] = "ASG uses Launch Configuration (not Launch Template)"
    except ClientError as exc:
        result["error"] = str(exc)
    return result


# ---------------------------------------------------------------------------
# Per-instance evaluation
# ---------------------------------------------------------------------------

def _evaluate_instance(instance: dict, clients: _AWSClients,
                        account_id: str, account_name: str, region: str) -> dict:
    """Run all 7 read-only checks and return a structured compliance report."""

    iid = instance["InstanceId"]
    tags = instance.get("Tags", [])

    # ── Basic info ─────────────────────────────────────────────────────────
    name_tag = tag_value(tags, "Name")
    state = safe_get(instance, "State", "Name", default="unknown")
    platform = instance.get("Platform", "linux")
    instance_type = instance.get("InstanceType", "unknown")
    ami_id = instance.get("ImageId", "unknown")
    az = safe_get(instance, "Placement", "AvailabilityZone", default="unknown")
    launch_time = str(instance.get("LaunchTime", ""))

    # ── Check 1: Metadata options ──────────────────────────────────────────
    meta_opts = instance.get("MetadataOptions", {})
    http_tokens = meta_opts.get("HttpTokens", "optional")
    hop_limit = meta_opts.get("HttpPutResponseHopLimit", 1)
    http_endpoint = meta_opts.get("HttpEndpoint", "disabled")
    imdsv2_enforced = http_tokens == "required"

    # ── Check 3: EKS ──────────────────────────────────────────────────────
    eks_cluster = tag_value(tags, EKS_TAG_KEY)
    is_eks_node = bool(eks_cluster)
    eks_hop_risk = is_eks_node and hop_limit < 2

    # ── Check 4: ASG ──────────────────────────────────────────────────────
    asg_name = tag_value(tags, ASG_TAG_KEY)
    is_asg = bool(asg_name)

    # ── Check 5: Launch Template ───────────────────────────────────────────
    lt_info = instance.get("LaunchTemplate", {})
    lt_id = lt_info.get("LaunchTemplateId")
    lt_version = lt_info.get("Version")
    lt_meta = None
    lt_compliant = None

    if is_asg and lt_id:
        asg_lt = _get_asg_launch_template(clients, asg_name)
        if not asg_lt["error"] and asg_lt["lt_id"]:
            lt_meta = _get_launch_template_metadata(
                clients, asg_lt["lt_id"], asg_lt["lt_version"]
            )
        else:
            lt_meta = _get_launch_template_metadata(clients, lt_id, lt_version or "$Default")
    elif lt_id:
        lt_meta = _get_launch_template_metadata(clients, lt_id, lt_version or "$Default")

    if lt_meta and not lt_meta.get("error"):
        lt_compliant = lt_meta["http_tokens"] == "required"

    # ── Check 6: AMI ──────────────────────────────────────────────────────
    ami = _get_ami_details(clients, ami_id)

    # ── Check 2: IMDSv1 CloudWatch usage ──────────────────────────────────
    cw = _get_imdsv1_usage(clients, iid)
    imdsv1_calls = cw["total_imdsv1_calls"]
    imdsv1_active = (imdsv1_calls or 0) > 0

    # ── Risk assessment ────────────────────────────────────────────────────
    risks: List[str] = []
    recommendations: List[str] = []

    if not imdsv2_enforced:
        risks.append("IMDSv2 NOT enforced (HttpTokens=optional)")
        recommendations.append("Set HttpTokens=required via modify-instance-metadata-options")

    if imdsv1_active:
        risks.append(
            f"Active IMDSv1 usage: {imdsv1_calls} calls in last {LOOKBACK_DAYS} days"
        )
        recommendations.append(
            "Identify IMDSv1 callers (old SDK/CLI, agents, scripts) before enforcing"
        )

    if eks_hop_risk:
        risks.append(f"EKS node with HopLimit={hop_limit} — pods lose metadata access")
        recommendations.append("Set HttpPutResponseHopLimit=2 for EKS nodes")

    if is_asg and lt_compliant is False:
        risks.append("Launch Template does NOT enforce IMDSv2 — new instances non-compliant")
        recommendations.append("Update Launch Template MetadataOptions: HttpTokens=required")

    if is_asg and lt_meta and lt_meta.get("error"):
        risks.append(f"Launch Template unreadable: {lt_meta['error']}")

    if ami["is_marketplace"]:
        risks.append("Marketplace AMI — verify vendor agents support IMDSv2")
        recommendations.append(
            "Review cloud-init logs for IMDSv1 calls; test enforcement on non-prod first"
        )

    if http_endpoint == "disabled":
        risks.append("Metadata endpoint DISABLED — no IMDS access")
        recommendations.append("Enable HttpEndpoint if the instance needs metadata access")

    if imdsv2_enforced and not risks:
        overall_status = "COMPLIANT"
    elif imdsv2_enforced and risks:
        overall_status = "NEEDS_REVIEW"
    else:
        overall_status = "NON_COMPLIANT"

    return {
        # Account context
        "account_id": account_id,
        "account_name": account_name,
        "region": region,
        # Instance identity
        "instance_id": iid,
        "name": name_tag,
        "state": state,
        "instance_type": instance_type,
        "az": az,
        "platform": platform,
        "launch_time": launch_time,
        # Metadata options
        "http_tokens": http_tokens,
        "hop_limit": hop_limit,
        "http_endpoint": http_endpoint,
        "imdsv2_enforced": imdsv2_enforced,
        # EKS
        "is_eks_node": is_eks_node,
        "eks_cluster": eks_cluster,
        "eks_hop_risk": eks_hop_risk,
        # ASG / LT
        "is_asg": is_asg,
        "asg_name": asg_name,
        "lt_id": lt_id or "",
        "lt_http_tokens": safe_get(lt_meta, "http_tokens", default="n/a") if lt_meta else "n/a",
        "lt_compliant": lt_compliant,
        # AMI
        "ami_id": ami_id,
        "ami_name": ami["name"],
        "ami_is_marketplace": ami["is_marketplace"],
        "ami_owner_alias": ami["owner_alias"],
        # IMDSv1 usage
        "imdsv1_calls_30d": imdsv1_calls,
        "imdsv1_active": imdsv1_active,
        # Assessment
        "risks": risks,
        "recommendations": recommendations,
        "overall_status": overall_status,
    }


# ---------------------------------------------------------------------------
# Public entrypoint (called by accounts.run_parallel worker)
# ---------------------------------------------------------------------------

def scan_target(target: AccountTarget, instance_ids: Optional[List[str]] = None) -> List[dict]:
    """
    Scan all EC2 instances in one AccountTarget (account + region).
    Returns a list of per-instance compliance reports.
    """
    if target.error or target.session is None:
        log.warning(
            "Skipping %s / %s — session unavailable: %s",
            target.account_id, target.region, target.error
        )
        return []

    clients = _AWSClients(target.session, target.region)
    log.debug("Fetching instances for %s / %s", target.account_id, target.region)
    instances = _list_instances(clients, instance_ids or [])

    if not instances:
        log.debug("No instances found in %s / %s.", target.account_id, target.region)
        return []

    reports = []
    for inst in instances:
        try:
            report = _evaluate_instance(
                inst, clients,
                target.account_id, target.account_name, target.region
            )
            reports.append(report)
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Error evaluating %s in %s / %s: %s",
                inst.get("InstanceId", "?"), target.account_id, target.region, exc
            )
    return reports
