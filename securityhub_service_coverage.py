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

For every unscanned service, a "Gap Category" column classifies *why* it's
unscanned, using Security Hub's full control catalog (list_security_control_
definitions, which lists every control the service supports in this region,
regardless of which standards are enabled):

    Not recorded by AWS Config       -- Config isn't tracking this service at
                                         all; Security Hub can never scan it
                                         under any standard until that changes.
    No Security Hub control exists   -- Config records it fine, but Security
                                         Hub has zero controls for this
                                         service in this region, for any
                                         standard. Enabling more standards
                                         won't fix this -- it's a structural
                                         ceiling in what Security Hub checks
                                         today.
    Control exists but not active    -- Security Hub does have at least one
                                         control for this service somewhere,
                                         but none of it is currently active in
                                         your account -- either the standard
                                         that contains it isn't enabled, or
                                         the specific control is disabled.
                                         This is the actionable bucket.

For rows specifically classified as "Control exists but not active in your
account", an additional column -- "Standard(s) With This Control Enabled" --
lists every standard (via ListStandardsControlAssociations) that has an
ENABLED association for a control on that service, whether or not you've
enabled that standard yourself. Each entry is tagged:
    "<Standard> (not enabled)"                       -- turning this standard
                                                         on would give you
                                                         this control.
    "<Standard> (already enabled -- control is
     disabled)"                                       -- you already have
                                                         this standard on;
                                                         the specific control
                                                         was disabled
                                                         (manually, or by
                                                         default for newly
                                                         released controls) --
                                                         re-enable the control
                                                         itself, not the
                                                         standard.
This column is intentionally left blank for every other row (already
scanned, not recorded by Config, or no control exists anywhere for that
service) since a standard recommendation isn't meaningful there.

Usage:
    pip install boto3 --break-system-packages   # if not already installed
    python3 securityhub_service_coverage.py --profile myprofile --region us-east-1 \
        --output securityhub_service_coverage.csv

Performance note: building the standard-availability column needs one API call
per relevant control (ListStandardsControlAssociations has no bulk form for
"all standards for this control"). Two things keep this fast:
  - Only controls belonging to services you actually have are queried, not
    Security Hub's entire catalog (skip --no-filter-controls to disable this
    and check every control regardless of relevance).
  - Those calls run concurrently via a thread pool (--workers, default 20).
Use --workers 1 to fall back to fully sequential calls if you hit throttling.

Required IAM permissions (read-only):
    tag:GetResources
    config:DescribeConfigRules
    config:GetDiscoveredResourceCounts
    securityhub:GetEnabledStandards
    securityhub:DescribeStandards
    securityhub:DescribeStandardsControls
    securityhub:ListSecurityControlDefinitions
    securityhub:ListStandardsControlAssociations
    sts:GetCallerIdentity
"""

import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from botocore.config import Config as BotoConfig

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


def get_all_control_ids(session):
    """
    Every SecurityControlId Security Hub supports in this region, regardless
    of which standards are enabled -- the full control catalog. Used to tell
    apart "no standard you've enabled covers this" from "Security Hub simply
    has no control for this, ever."
    """
    client = session.client("securityhub")
    control_ids = set()
    try:
        paginator = client.get_paginator("list_security_control_definitions")
        for page in paginator.paginate():
            for defn in page.get("SecurityControlDefinitions", []):
                cid = defn.get("SecurityControlId")
                if cid:
                    control_ids.add(cid)
    except ClientError as e:
        print(f"  [warn] Security Hub list_security_control_definitions failed: {e}")
    return control_ids


def get_control_standard_availability(session, control_ids, name_map, max_workers=20):
    """
    For every control in `control_ids`, find every standard (enabled or not)
    that includes it with AssociationStatus == 'ENABLED' -- i.e. every
    standard where turning it on would actually give you this control. This
    powers the "you could get this by enabling standard X" recommendation.

    ListStandardsControlAssociations has no bulk form ("all standards for
    this control" is one call per control), so this fans the calls out
    across a thread pool instead of doing them one at a time -- these are
    independent, read-only, network-bound calls, so concurrency is safe and
    turns e.g. 300 sequential round-trips into ~300/max_workers.
    """
    client = session.client(
        "securityhub",
        config=BotoConfig(
            max_pool_connections=max(max_workers, 10),
            retries={"max_attempts": 10, "mode": "adaptive"},
        ),
    )

    def fetch_one(cid):
        standards_for_control = set()
        try:
            paginator = client.get_paginator("list_standards_control_associations")
            for page in paginator.paginate(SecurityControlId=cid):
                for assoc in page.get("StandardsControlAssociationSummaries", []):
                    if assoc.get("AssociationStatus") == "ENABLED":
                        arn = assoc.get("StandardsArn")
                        standards_for_control.add(name_map.get(arn, arn))
        except ClientError as e:
            print(f"  [warn] list_standards_control_associations failed for {cid}: {e}")
        return cid, standards_for_control

    control_to_standards = {}
    workers = max(1, max_workers)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(fetch_one, cid) for cid in sorted(control_ids)]
        for future in as_completed(futures):
            cid, standards_for_control = future.result()
            control_to_standards[cid] = standards_for_control
    return control_to_standards


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


# AWS Config resource types and Security Hub control IDs sometimes use
# different names for the same real-world service. Config/tag-derived service
# name (normalized) -> the control-ID-prefix name (normalized) it should be
# looked up under when attributing standard coverage. Add to this table if you
# spot more "Unknown" rows that are really just a naming mismatch.
CONFIG_TO_CONTROL_ALIAS = {
    "elasticloadbalancing": "elb",          # classic ELB -> ELB.* controls
    "elasticloadbalancingv2": "elb",        # ALB/NLB -> ELB.* controls
    "events": "eventbridge",                # AWS::Events::* -> EventBridge.* controls
    "wafv2": "waf",                         # AWS::WAFv2::* -> WAF.* controls
    "wafregional": "waf",                   # AWS::WAFRegional::* -> WAF.* controls
    "kinesisfirehose": "datafirehose",      # AWS::KinesisFirehose::* -> DataFirehose.* controls
    "firehose": "datafirehose",             # ARN service name "firehose" -> DataFirehose.* controls
}


def control_lookup_key(config_domain_key):
    """Map a Config/tag-derived service key to the key it'd appear under in
    the control-ID-derived mapping, via the known alias table above."""
    return CONFIG_TO_CONTROL_ALIAS.get(config_domain_key, config_domain_key)


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


def build_service_available_standards(all_control_ids, control_to_standards):
    """
    {normalized_service: set(standard_names)} for every standard that would
    give you at least one control for that service if you enabled it --
    regardless of whether you've enabled it already.
    """
    mapping = {}
    for cid in all_control_ids:
        svc = normalize(service_from_control_id(cid))
        mapping.setdefault(svc, set()).update(control_to_standards.get(cid, set()))
    return mapping


GAP_NOT_RECORDED = "Not recorded by AWS Config"
GAP_NO_CONTROL_EXISTS = "No Security Hub control exists (any standard)"
GAP_CONTROL_INACTIVE = "Control exists but not active in your account"
GAP_NONE = ""  # actively scanned -- not a gap


def classify_gap(recorded, scanned, key, all_supported_services):
    if scanned == "Yes":
        return GAP_NONE
    if recorded == "No":
        return GAP_NOT_RECORDED
    if key not in all_supported_services:
        return GAP_NO_CONTROL_EXISTS
    return GAP_CONTROL_INACTIVE


def build_coverage_rows(
    tagged_services,
    config_types,
    covered_types,
    service_to_standards,
    all_supported_services,
    service_available_standards,
    enabled_standard_names,
):
    config_service_counts = {}
    for rt, count in config_types.items():
        svc = service_from_resource_type(rt)
        config_service_counts[svc] = config_service_counts.get(svc, 0) + count

    covered_services = {normalize(service_from_resource_type(rt)) for rt in covered_types}
    config_services_norm = {normalize(s) for s in config_service_counts}
    enabled_set = set(enabled_standard_names)

    all_services = sorted(set(tagged_services) | set(config_service_counts))

    rows = []
    for svc in all_services:
        key = normalize(svc)
        lookup_key = control_lookup_key(key)
        tagged_count = tagged_services.get(svc, "")
        cfg_count = config_service_counts.get(svc, "")
        recorded = "Yes" if key in config_services_norm else "No"
        scanned = "Yes" if key in covered_services else "No"
        standards = sorted(service_to_standards.get(lookup_key, []))
        if scanned != "Yes":
            # Not actively scanned -> no standard is actually covering it, even
            # if that service has an ENABLED control somewhere (e.g. a
            # different resource type under the same service that isn't the
            # one you have, or one whose Config rule doesn't scope this type).
            standards_str = ""
        elif standards:
            standards_str = ", ".join(standards)
        else:
            standards_str = "Unknown (active control found, standard couldn't be confidently attributed)"
        gap_category = classify_gap(recorded, scanned, lookup_key, all_supported_services)

        # Only populated for GAP_CONTROL_INACTIVE rows, per request -- blank
        # everywhere else (already scanned, not recorded, or no control exists
        # at all). Deliberately NOT subtracting your already-enabled standards
        # here: for this exact category, the responsible standard is often
        # already enabled and it's the specific control that's disabled, so
        # subtracting enabled standards was hiding the very answer being asked
        # for. Each standard is tagged so it's clear whether the fix is
        # "enable this standard" or "re-enable this control under a standard
        # you already have on."
        available_str = ""
        if gap_category == GAP_CONTROL_INACTIVE:
            avail = service_available_standards.get(lookup_key, set())
            labeled = []
            for name in sorted(avail):
                if name in enabled_set:
                    labeled.append(f"{name} (already enabled -- control is disabled)")
                else:
                    labeled.append(f"{name} (not enabled)")
            available_str = "; ".join(labeled)

        rows.append([svc, tagged_count, recorded, cfg_count, scanned, standards_str, gap_category, available_str])
    return rows


CSV_HEADERS = [
    "Service",
    "Tagged Resource Count",
    "Recorded by AWS Config?",
    "Config Discovered Count",
    "Actively Scanned by Security Hub?",
    "Covering Standard(s)",
    "Gap Category",
    "Standard(s) With This Control Enabled (only for 'Control exists but not active' rows)",
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
    parser.add_argument("--workers", type=int, default=20,
                         help="Concurrent threads for the standard-availability lookup (default 20). "
                              "Use 1 to go fully sequential if you hit API throttling.")
    parser.add_argument("--no-filter-controls", action="store_true",
                         help="Check standard-availability for every control in Security Hub's catalog, "
                              "not just services you actually have. Much slower; mainly for debugging.")
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

    print("1/7  Pulling tagged resource inventory (Resource Groups Tagging API)...")
    tagged_services = get_tagged_service_counts(session)

    print("2/7  Pulling AWS Config discovered resource counts...")
    config_types = get_config_discovered_resource_counts(session)

    print("3/7  Reading live Security Hub Config rules (active scan scope)...")
    covered_types = get_securityhub_active_resource_types(session)

    print("4/7  Listing enabled standards and control status...")
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

    print("5/7  Pulling full Security Hub control catalog (any standard, any enablement)...")
    all_control_ids = get_all_control_ids(session)
    # Used for the "No Security Hub control exists" classification -- keep this
    # against the FULL catalog regardless of filtering below, so that check
    # stays accurate.
    all_supported_services = {normalize(service_from_control_id(cid)) for cid in all_control_ids}

    if args.no_filter_controls:
        controls_to_check = all_control_ids
    else:
        config_service_keys = {service_from_resource_type(rt) for rt in config_types}
        relevant_services = {
            control_lookup_key(normalize(s)) for s in (set(tagged_services) | config_service_keys)
        }
        controls_to_check = {
            cid for cid in all_control_ids
            if normalize(service_from_control_id(cid)) in relevant_services
        }

    print(f"6/7  Checking which standard(s) each of the {len(controls_to_check)} relevant controls "
          f"(of {len(all_control_ids)} total) belongs to, using {args.workers} concurrent workers...")
    control_to_standards = get_control_standard_availability(
        session, controls_to_check, name_map, max_workers=args.workers
    )
    service_available_standards = build_service_available_standards(controls_to_check, control_to_standards)

    print("7/7  Building coverage table and writing CSV...")
    service_to_standards = build_service_to_standards(all_controls_by_standard)
    rows = build_coverage_rows(
        tagged_services,
        config_types,
        covered_types,
        service_to_standards,
        all_supported_services,
        service_available_standards,
        standard_names,
    )
    write_csv(rows, args.output)

    covered_count = sum(1 for r in rows if r[4] == "Yes")
    gap_counts = {}
    for r in rows:
        cat = r[6]
        if cat:
            gap_counts[cat] = gap_counts.get(cat, 0) + 1

    print(f"\nDone. {len(rows)} services written to: {args.output}")
    print(f"  Enabled standards: {', '.join(standard_names) or 'none detected'}")
    print(f"  Services actively scanned by Security Hub: {covered_count} / {len(rows)}")
    for cat, count in sorted(gap_counts.items(), key=lambda x: -x[1]):
        print(f"    - {cat}: {count}")
    if not enabled_subs:
        print("  NOTE: no Security Hub standards were detected as enabled in this region.")


if __name__ == "__main__":
    main()
