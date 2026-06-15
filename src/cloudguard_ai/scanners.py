from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudguard_ai.aws import client
from cloudguard_ai.models import Finding

INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}
SENSITIVE_PORTS = {
    22: ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "HIGH"),
    5432: ("PostgreSQL", "HIGH"),
    6379: ("Redis", "HIGH"),
}
ADMINISTRATOR_ACCESS_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ACCESS_KEY_MAX_AGE_DAYS = 90


class ScanError(RuntimeError):
    pass


def scan_security_groups(session, region: str) -> list[Finding]:
    ec2 = client(session, "ec2", region)
    findings: list[Finding] = []

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        pages = paginator.paginate()
        for page in pages:
            for group in page.get("SecurityGroups", []):
                findings.extend(_security_group_findings(group, region))
    except ClientError as exc:
        raise ScanError(f"Unable to scan security groups in {region}: {exc}") from exc

    return findings


def _security_group_findings(group: dict, region: str) -> list[Finding]:
    findings: list[Finding] = []
    group_id = group.get("GroupId", "unknown")
    group_name = group.get("GroupName", "unknown")

    for rule in group.get("IpPermissions", []):
        open_cidrs = _open_cidrs(rule)
        if not open_cidrs:
            continue

        for port in _matching_sensitive_ports(rule):
            service_name, severity = SENSITIVE_PORTS[port]
            findings.append(
                Finding(
                    service="EC2",
                    resource=f"{group_name} ({group_id})",
                    severity=severity,
                    issue=f"{service_name} port {port} is open to the internet: {', '.join(open_cidrs)}",
                    region=region,
                    risk_explanation=(
                        f"Port {port} is commonly used for {service_name}. Exposing it to the internet "
                        "lets attackers scan, brute-force, and attempt direct exploitation."
                    ),
                    business_impact=(
                        "A compromise through this network path can cause unauthorized access, "
                        "data exposure, downtime, compliance issues, and incident response costs."
                    ),
                    recommended_fix=(
                        "Remove the public CIDR and allow access only from a VPN, bastion host, "
                        "trusted corporate IP range, or an approved private security group."
                    ),
                    aws_cli_remediation=_security_group_remediation_command(group_id, rule, open_cidrs, region),
                )
            )

    return findings


def _matching_sensitive_ports(rule: dict) -> list[int]:
    protocol = rule.get("IpProtocol", "unknown")
    if protocol not in {"tcp", "6", "-1"}:
        return []

    if protocol == "-1":
        return sorted(SENSITIVE_PORTS)

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is None or to_port is None:
        return []

    return sorted(port for port in SENSITIVE_PORTS if from_port <= port <= to_port)


def _security_group_remediation_command(group_id: str, rule: dict, open_cidrs: list[str], region: str) -> str:
    protocol = rule.get("IpProtocol", "-1")
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    base = (
        "aws ec2 revoke-security-group-ingress "
        f"--group-id {group_id} "
        f"--ip-protocol {protocol} "
    )

    if protocol != "-1" and from_port is not None and to_port is not None:
        base += f"--from-port {from_port} --to-port {to_port} "

    cidr_flag = "--cidr"
    cidr = open_cidrs[0]
    if ":" in cidr:
        cidr_flag = "--cidr-ipv6"

    return f"{base}{cidr_flag} {cidr} --region {region}"


def _open_cidrs(rule: dict) -> list[str]:
    cidrs = [item.get("CidrIp") for item in rule.get("IpRanges", [])]
    cidrs.extend(item.get("CidrIpv6") for item in rule.get("Ipv6Ranges", []))
    return sorted(cidr for cidr in cidrs if cidr in INTERNET_CIDRS)


def _format_port_range(rule: dict) -> str:
    protocol = rule.get("IpProtocol", "unknown")
    if protocol == "-1":
        return "all traffic"

    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is None or to_port is None:
        return f"protocol {protocol}"
    if from_port == to_port:
        return f"{protocol}/{from_port}"
    return f"{protocol}/{from_port}-{to_port}"


def scan_rds(session, region: str) -> list[Finding]:
    rds = client(session, "rds", region)
    findings: list[Finding] = []

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                if instance.get("PubliclyAccessible"):
                    findings.append(
                        Finding(
                            service="RDS",
                            resource=instance.get("DBInstanceIdentifier", "unknown"),
                            severity="HIGH",
                            issue="DB instance is publicly accessible",
                            region=region,
                            risk_explanation=(
                                "The database has a public network path. Even with passwords "
                                "or security groups, a public endpoint increases brute-force, "
                                "exploit, and misconfiguration risk."
                            ),
                            business_impact=(
                                "A compromised database can expose customer data, application "
                                "secrets, financial records, or regulated information."
                            ),
                            recommended_fix=(
                                "Move the database into private subnets, disable public "
                                "accessibility, and allow access only from application or "
                                "administration networks."
                            ),
                            aws_cli_remediation=(
                                "aws rds modify-db-instance "
                                f"--db-instance-identifier {instance.get('DBInstanceIdentifier', 'unknown')} "
                                "--no-publicly-accessible --apply-immediately "
                                f"--region {region}"
                            ),
                        )
                    )
    except ClientError as exc:
        raise ScanError(f"Unable to scan RDS in {region}: {exc}") from exc

    return findings


def scan_iam(session) -> list[Finding]:
    iam = client(session, "iam", "us-east-1")
    findings: list[Finding] = []

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user.get("UserName", "unknown")
                if _has_administrator_access(iam, user_name):
                    findings.append(_administrator_access_finding(user_name))
                findings.extend(_old_access_key_findings(iam, user_name))
    except ClientError as exc:
        raise ScanError(f"Unable to scan IAM users: {exc}") from exc

    return findings


def _has_administrator_access(iam, user_name: str) -> bool:
    attached_policies = iam.get_paginator("list_attached_user_policies")
    for page in attached_policies.paginate(UserName=user_name):
        for policy in page.get("AttachedPolicies", []):
            if policy.get("PolicyArn") == ADMINISTRATOR_ACCESS_ARN:
                return True

    user_policies = iam.get_paginator("list_user_policies")
    for page in user_policies.paginate(UserName=user_name):
        for policy_name in page.get("PolicyNames", []):
            policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            if _policy_allows_admin(policy.get("PolicyDocument", {})):
                return True

    return False


def _policy_allows_admin(policy_document: dict) -> bool:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        if "*" in actions and "*" in resources:
            return True

    return False


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _administrator_access_finding(user_name: str) -> Finding:
    return Finding(
        service="IAM",
        resource=user_name,
        severity="CRITICAL",
        issue="IAM user has AdministratorAccess permissions",
        region="global",
        risk_explanation=(
            "Administrator permissions allow full control of the AWS account. If this user or "
            "its credentials are compromised, an attacker can create, delete, or change resources."
        ),
        business_impact=(
            "Account takeover can lead to data loss, service disruption, privilege escalation, "
            "unexpected cloud spend, and compliance violations."
        ),
        recommended_fix=(
            "Remove AdministratorAccess from the user and replace it with least-privilege role-based access."
        ),
        aws_cli_remediation=(
            "aws iam detach-user-policy "
            f"--user-name {user_name} "
            "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ),
    )


def _old_access_key_findings(iam, user_name: str) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    paginator = iam.get_paginator("list_access_keys")

    for page in paginator.paginate(UserName=user_name):
        for key in page.get("AccessKeyMetadata", []):
            created = key.get("CreateDate")
            if created is None:
                continue
            age_days = (now - created).days
            if age_days > ACCESS_KEY_MAX_AGE_DAYS:
                access_key_id = key.get("AccessKeyId", "unknown")
                findings.append(
                    Finding(
                        service="IAM",
                        resource=f"{user_name} ({access_key_id})",
                        severity="MEDIUM",
                        issue=f"Access key is {age_days} days old",
                        region="global",
                        risk_explanation=(
                            "Long-lived access keys are more likely to be leaked, copied, or forgotten "
                            "in old scripts and developer machines."
                        ),
                        business_impact=(
                            "A leaked key can allow unauthorized AWS API access, data exposure, "
                            "resource changes, and unexpected cloud charges."
                        ),
                        recommended_fix=(
                            "Rotate the access key, update dependent workloads, and deactivate then delete the old key."
                        ),
                        aws_cli_remediation=(
                            "aws iam update-access-key "
                            f"--user-name {user_name} "
                            f"--access-key-id {access_key_id} "
                            "--status Inactive"
                        ),
                    )
                )

    return findings


def scan_cloudtrail(session, region: str) -> list[Finding]:
    cloudtrail = client(session, "cloudtrail", region)

    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=True).get("trailList", [])
        if not trails:
            return [_cloudtrail_disabled_finding(region)]

        for trail in trails:
            status = cloudtrail.get_trail_status(Name=trail.get("TrailARN", trail.get("Name")))
            if status.get("IsLogging"):
                return []
    except ClientError as exc:
        raise ScanError(f"Unable to scan CloudTrail in {region}: {exc}") from exc

    return [_cloudtrail_disabled_finding(region)]


def _cloudtrail_disabled_finding(region: str) -> Finding:
    return Finding(
        service="CloudTrail",
        resource="account",
        severity="CRITICAL",
        issue="No active CloudTrail logging detected",
        region=region,
        risk_explanation=(
            "Without active CloudTrail logging, AWS API activity may not be recorded for investigation, "
            "alerting, or audit evidence."
        ),
        business_impact=(
            "Security incidents become harder to investigate, compliance evidence may be incomplete, "
            "and unauthorized changes can go unnoticed."
        ),
        recommended_fix=(
            "Create or enable a multi-region CloudTrail trail that writes to a protected S3 bucket."
        ),
        aws_cli_remediation=(
            "aws cloudtrail start-logging --name <trail-name> "
            f"--region {region}"
        ),
    )


def scan_s3(session) -> list[Finding]:
    s3 = client(session, "s3", "us-east-1")
    findings: list[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as exc:
        raise ScanError(f"Unable to list S3 buckets: {exc}") from exc

    for bucket in buckets:
        bucket_name = bucket["Name"]
        if not _has_full_public_access_block(s3, bucket_name):
            findings.append(
                Finding(
                    service="S3",
                    resource=bucket_name,
                    severity="MEDIUM",
                    issue="Bucket does not have all Block Public Access settings enabled",
                    region="global",
                    risk_explanation=(
                        "Without full Block Public Access, future ACL or bucket policy changes "
                        "could accidentally expose objects to the internet."
                    ),
                    business_impact=(
                        "Accidental public bucket access can disclose backups, logs, customer "
                        "files, application assets, or other sensitive business data."
                    ),
                    recommended_fix=(
                        "Enable all four S3 Block Public Access settings unless the bucket has "
                        "a reviewed and documented public hosting requirement."
                    ),
                    aws_cli_remediation=(
                        "aws s3api put-public-access-block "
                        f"--bucket {bucket_name} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                )
            )

    return findings


def _has_full_public_access_block(s3, bucket_name: str) -> bool:
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfigurationError"}:
            return False
        raise ScanError(f"Unable to read S3 public access block for {bucket_name}: {exc}") from exc

    required_flags = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    return all(config.get(flag) is True for flag in required_flags)
