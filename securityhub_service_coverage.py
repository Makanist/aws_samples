#!/usr/bin/env python3
"""
securityhub_service_coverage.py

Produces a single CSV: one row per AWS service you're actually using, showing
whether Security Hub is actively scanning it, and -- if so -- which of your
currently ENABLED standards (NIST 800-53, CIS, FSBP, PCI, whichever you have
turned on) is responsible for that coverage.

How "covered" is determined (two independent signals, combined):

  1. LIVE SCAN CHECK (authoritative "yes/no"): Security Hub creates a real AWS
     Config rule (name prefix "securityhub-") for every currently-ENABLED
     control that needs one. This script reads those rules directly and
     extracts which resource types (hence which services) have at least one
     actively-firing rule right now. This is what actually determines
     Yes/No -- it reflects your live account, not a static doc.

  2. STANDARD ATTRIBUTION (best-effort "which standard"): for every standard
     you have enabled, this script pulls its full control list along with
     each control's live ENABLED/DISABLED status (via Security Hub's
     DescribeStandardsControls). Security Hub control IDs are namespaced by
     service, e.g. "EC2.2", "S3.1", "IAM.5" -- the prefix before the dot is
     the service. So for a service confirmed covered by signal #1, this
     script looks at which enabled standards have at least one ENABLED
     control with that service prefix, and lists those as the covering
     standard(s).

     Caveat: the service-prefix match is a reasonable approximation, not a
     byte-exact API guarantee -- a handful of controls could theoretically be
     attributed to the wrong specific standard if a service has controls
     split unevenly across standards. If a service shows "Yes" but no
     standard could be confidently attributed, it's flagged as "Unknown" in
     the Covering Standard(s) column rather than guessed. Cross-check the
     "All Standards Control Status" companion sheet from
     securityhub_gap_report.py if you need control-level precision instead of
     service-level.

Usage:
    pip install boto3 --break-system-packages   # if not already installed
    python3 securityhub_service_coverage.py --profile myprofile --region us-east-1 \
        --output securityhub_service_coverage.csv

Required IAM permissions (read-only):
    tag:GetResources
    config:DescribeConfigRules
    config:GetDiscoveredResourceCounts
    securityhub:GetEnabledStandards
    securityhub:DescribeStandards
    securityhub:DescribeStandardsControls
    sts:GetCallerIdentity
"""

import argparse
import csv
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


# --------------------------------------------------------------------------
# AWS data collection
# --------------------------------------------------------------------------

def get_session(profile, region):
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def get_account_context(session):
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    return ident["Account"], session.region_name


def arn_to_service(arn):
    parts = arn.split(":")
    return parts[2] if len(parts) >= 3 else None


def get_tagged_service_counts(session):
    """Service-level inventory from the Resource Groups Tagging API."""
    client = session.client("resourcegroupstaggingapi")
    services = {}
    paginator = client.get_paginator("get_resources")
    try:
        for page in paginator.paginate(ResourcesPerPage=100):
            for mapping in page.get("ResourceTagMappingList", []):
                service = arn_to_service(mapping.get("ResourceARN", ""))
                if service:
                    services[service] = services.get(service, 0) + 1
    except ClientError as e:
        print(f"  [warn] Resource Groups Tagging API call failed: {e}")
    return services


def get_config_discovered_resource_counts(session):
    """resourceType -> count, e.g. 'AWS::EC2::Instance' -> 42. Manual pagination
    since this API doesn't support boto3's automatic paginator."""
    client = session.client("config")
    counts = {}
    try:
        next_token = None
        while True:
            kwargs = {"limit": 100}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = client.get_discovered_resource_counts(**kwargs)
            for item in resp.get("resourceCounts", []):
                counts[item["resourceType"]] = item["count"]
            next_token = resp.get("nextToken")
            if not next_token:
                break
    except ClientError as e:
        print(f"  [warn] Config get_discovered_resource_counts failed: {e}")
        print("         (Is AWS Config enabled/recording in this region?)")
    return counts


def get_securityhub_active_resource_types(session):
    """Resource types with at least one live 'securityhub-*' Config rule
    scoped to them -- i.e., actively scanned right now, across whatever
    standards are enabled."""
    client = session.client("config")
    covered_types = set()
    try:
        paginator = client.get_paginator("describe_config_rules")
        for page in paginator.paginate():
            for rule in page.get("ConfigRules", []):
                name = rule.get("ConfigRuleName", "")
                if not name.startswith("securityhub-"):
                    continue
                for t in rule.get("Scope", {}).get("ComplianceResourceTypes", []):
                    covered_types.add(t)
    except ClientError as e:
        print(f"  [warn] Config describe_config_rules failed: {e}")
    return covered_types


def get_enabled_standards(session):
    client = session.client("securityhub")
    subs = []
    try:
        paginator = client.get_paginator("get_enabled_standards")
        for page in paginator.paginate():
            subs.extend(page.get("StandardsSubscriptions", []))
    except ClientError as e:
        print(f"  [warn] Security Hub get_enabled_standards failed: {e}")
    return subs


def get_standards_name_map(session):
    client = session.client("securityhub")
    name_map = {}
    try:
        paginator = client.get_paginator("describe_standards")
        for page in paginator.paginate():
            for std in page.get("Standards", []):
                name_map[std.get("StandardsArn")] = std.get("Name") or std.get("StandardsArn")
    except ClientError as e:
        print(f"  [warn] Security Hub describe_standards failed: {e}")
    return name_map


def get_controls_for_standard(session, subscription_arn):
    client = session.client("securityhub")
    controls = []
    try:
        paginator = client.get_paginator("describe_standards_controls")
        for page in paginator.paginate(StandardsSubscriptionArn=subscription_arn):
            controls.extend(page.get("Controls", []))
    except ClientError as e:
        print(f"  [warn] describe_standards_controls failed for {subscription_arn}: {e}")
    return controls


# --------------------------------------------------------------------------
# Business logic
# --------------------------------------------------------------------------

def service_from_resource_type(resource_type):
    """'AWS::EC2::Instance' -> 'ec2' """
    parts = resource_type.split("::")
    return parts[1].lower() if len(parts) > 1 else resource_type.lower()


def service_from_control_id(control_id):
    """'EC2.2' -> 'ec2', 'IAM.5' -> 'iam' """
    return control_id.split(".")[0].lower() if "." in control_id else control_id.lower()


def normalize(svc):
    return svc.lower().replace("-", "").replace("_", "")


def build_service_to_standards(all_controls_by_standard):
    """
    all_controls_by_standard: list of (standard_name, control_id, status)
    Returns: {normalized_service: set(standard_names)} for services with at
    least one ENABLED control in that standard.
    """
    mapping = {}
    for standard_name, control_id, status in all_controls_by_standard:
        if status != "ENABLED":
            continue
        svc = normalize(service_from_control_id(control_id))
        mapping.setdefault(svc, set()).add(standard_name)
    return mapping


def build_coverage_rows(tagged_services, config_types, covered_types, service_to_standards):
    config_service_counts = {}
    for rt, count in config_types.items():
        svc = service_from_resource_type(rt)
        config_service_counts[svc] = config_service_counts.get(svc, 0) + count

    covered_services = {normalize(service_from_resource_type(rt)) for rt in covered_types}
    config_services_norm = {normalize(s) for s in config_service_counts}

    all_services = sorted(set(tagged_services) | set(config_service_counts))

    rows = []
    for svc in all_services:
        key = normalize(svc)
        tagged_count = tagged_services.get(svc, "")
        cfg_count = config_service_counts.get(svc, "")
        recorded = "Yes" if key in config_services_norm else "No"
        scanned = "Yes" if key in covered_services else "No"
        standards = sorted(service_to_standards.get(key, []))
        if scanned == "Yes" and not standards:
            standards_str = "Unknown (active control found, standard couldn't be confidently attributed)"
        elif standards:
            standards_str = ", ".join(standards)
        else:
            standards_str = ""
        rows.append([svc, tagged_count, recorded, cfg_count, scanned, standards_str])
    return rows


CSV_HEADERS = [
    "Service",
    "Tagged Resource Count",
    "Recorded by AWS Config?",
    "Config Discovered Count",
    "Actively Scanned by Security Hub?",
    "Covering Standard(s)",
]


def write_csv(rows, output_path):
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        writer.writerows(rows)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", default=None, help="AWS named profile to use")
    parser.add_argument("--region", default=None, help="AWS region to inspect")
    parser.add_argument("--output", default="securityhub_service_coverage.csv", help="Output .csv path")
    args = parser.parse_args()

    try:
        session = get_session(args.profile, args.region)
        account_id, region = get_account_context(session)
    except NoCredentialsError:
        print("No AWS credentials found. Pass --profile or configure your environment.")
        sys.exit(1)
    except ClientError as e:
        print(f"Could not authenticate / call STS: {e}")
        sys.exit(1)

    if not region:
        print("No region resolved. Pass --region explicitly (e.g. --region us-east-1).")
        sys.exit(1)

    print(f"Account: {account_id}   Region: {region}")

    print("1/5  Pulling tagged resource inventory (Resource Groups Tagging API)...")
    tagged_services = get_tagged_service_counts(session)

    print("2/5  Pulling AWS Config discovered resource counts...")
    config_types = get_config_discovered_resource_counts(session)

    print("3/5  Reading live Security Hub Config rules (active scan scope)...")
    covered_types = get_securityhub_active_resource_types(session)

    print("4/5  Listing enabled standards and control status...")
    enabled_subs = get_enabled_standards(session)
    name_map = get_standards_name_map(session)
    all_controls_by_standard = []
    standard_names = []
    for sub in enabled_subs:
        arn = sub.get("StandardsArn", "")
        sub_arn = sub.get("StandardsSubscriptionArn", "")
        name = name_map.get(arn, arn)
        standard_names.append(name)
        for c in get_controls_for_standard(session, sub_arn):
            all_controls_by_standard.append((name, c.get("ControlId", ""), c.get("ControlStatus", "UNKNOWN")))

    print("5/5  Building coverage table and writing CSV...")
    service_to_standards = build_service_to_standards(all_controls_by_standard)
    rows = build_coverage_rows(tagged_services, config_types, covered_types, service_to_standards)
    write_csv(rows, args.output)

    covered_count = sum(1 for r in rows if r[4] == "Yes")
    print(f"\nDone. {len(rows)} services written to: {args.output}")
    print(f"  Enabled standards: {', '.join(standard_names) or 'none detected'}")
    print(f"  Services actively scanned by Security Hub: {covered_count} / {len(rows)}")
    if not enabled_subs:
        print("  NOTE: no Security Hub standards were detected as enabled in this region.")


if __name__ == "__main__":
    main()
