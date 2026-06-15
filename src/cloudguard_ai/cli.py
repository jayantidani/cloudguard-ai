from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import sys

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound
from rich.console import Console
from rich.table import Table

from cloudguard_ai.aws import client, create_session
from cloudguard_ai.models import Finding, ScanSummary
from cloudguard_ai.scanners import ScanError, scan_cloudtrail, scan_iam, scan_rds, scan_s3, scan_security_groups

console = Console()
REPORT_PATH = Path("reports") / "cloudguard-report.html"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SCORE_DEDUCTIONS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1,
}
DEMO_ACCOUNT_ID = "********4755"
DEMO_IAM_USER = "demo-user"
DEMO_ACCESS_KEY_ID = "AKIA********DEMO"
DEMO_S3_BUCKET = "sample-security-bucket"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudguard-ai",
        description="Scan AWS for common public exposure risks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run AWS security checks.")
    scan_parser.add_argument("--profile", help="AWS profile name to use.")
    scan_parser.add_argument("--region", help="AWS region to scan. Defaults to the active AWS region.")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        return run_scan(profile=args.profile, region=args.region)

    return 2


def run_scan(profile: str | None, region: str | None) -> int:
    try:
        session = create_session(profile=profile, region=region)
        scan_region = session.region_name
        if not scan_region:
            console.print("[red]No AWS region found. Pass --region or configure a default region.[/red]")
            return 2

        findings = []
        findings.extend(scan_security_groups(session, scan_region))
        findings.extend(scan_rds(session, scan_region))
        findings.extend(scan_s3(session))
        findings.extend(scan_iam(session))
        findings.extend(scan_cloudtrail(session, scan_region))
        summary = build_scan_summary(session, findings)
    except ProfileNotFound as exc:
        console.print(f"[red]{exc}[/red]")
        return 2
    except NoCredentialsError:
        console.print("[red]No AWS credentials found. Run aws configure or pass --profile.[/red]")
        return 2
    except (BotoCoreError, ScanError) as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    render_findings(findings, summary)
    write_html_report(findings, summary, REPORT_PATH)
    console.print(f"[green]HTML report written to {REPORT_PATH}[/green]")
    return 1 if findings else 0


def build_scan_summary(session, findings: list[Finding]) -> ScanSummary:
    account_id = get_account_id(session)
    return ScanSummary(
        account_id=account_id,
        scan_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_findings=len(findings),
        security_score=calculate_security_score(findings),
    )


def get_account_id(session) -> str:
    sts = client(session, "sts", "us-east-1")
    try:
        return sts.get_caller_identity().get("Account", "unknown")
    except (BotoCoreError, ClientError) as exc:
        raise ScanError(f"Unable to read AWS account ID: {exc}") from exc


def calculate_security_score(findings: list[Finding]) -> int:
    deductions = sum(SCORE_DEDUCTIONS.get(finding.severity, 0) for finding in findings)
    return max(0, 100 - deductions)


def render_findings(findings: list[Finding], summary: ScanSummary) -> None:
    render_scan_summary(summary)
    render_summary(findings)

    table = Table(title="CloudGuard AI Findings")
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Resource", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Region", style="magenta", no_wrap=True)
    table.add_column("Issue", style="yellow")
    table.add_column("Risk", style="white")
    table.add_column("Business Impact", style="white")
    table.add_column("Recommended Fix", style="green")
    table.add_column("AWS CLI Remediation", style="blue")

    for finding in findings:
        table.add_row(
            finding.service,
            finding.resource,
            finding.severity,
            finding.region,
            finding.issue,
            finding.risk_explanation,
            finding.business_impact,
            finding.recommended_fix,
            finding.aws_cli_remediation,
        )

    if findings:
        console.print(table)
    else:
        console.print("[green]No findings detected.[/green]")


def render_scan_summary(summary: ScanSummary) -> None:
    table = Table(title="Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("AWS Account ID", summary.account_id)
    table.add_row("Scan Timestamp", summary.scan_timestamp)
    table.add_row("Total Findings", str(summary.total_findings))
    table.add_row("Security Score", f"{summary.security_score}/100")
    console.print(table)


def render_summary(findings: list[Finding]) -> None:
    counts = severity_counts(findings)
    table = Table(title="Severity Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    for severity in SEVERITIES:
        table.add_row(severity, str(counts[severity]))

    console.print(table)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts.get(severity, 0) for severity in SEVERITIES}


def write_html_report(findings: list[Finding], summary: ScanSummary, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = severity_counts(findings)
    display_summary = demo_scan_summary(summary)
    finding_cards = "\n".join(_finding_card(demo_finding(finding)) for finding in findings)
    if not finding_cards:
        finding_cards = '<div class="empty">No findings detected.</div>'

    summary_cards = "\n".join(
        f'<div class="summary-card {severity.lower()}"><span>{severity}</span><strong>{counts[severity]}</strong></div>'
        for severity in SEVERITIES
    )

    path.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CloudGuard AI Report</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{ margin: 0; font-family: Arial, sans-serif; color: #172033; background: #eef2f7; }}
    header {{ padding: 32px; background: #111827; color: white; }}
    header a {{ color: white; }}
    main {{ padding: 24px 32px 40px; max-width: 1280px; margin: 0 auto; }}
    h1 {{ margin: 0 0 8px; font-size: 32px; }}
    h2 {{ margin: 28px 0 14px; font-size: 20px; }}
    .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin: 24px 0; }}
    .metric, .summary-card, .finding-card {{ background: white; border-radius: 8px; box-shadow: 0 1px 5px #0001; }}
    .metric {{ padding: 16px; border: 1px solid #dfe5ee; }}
    .metric span, .summary-card span {{ display: block; color: #5b6577; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    .metric strong, .summary-card strong {{ display: block; margin-top: 8px; font-size: 28px; color: #111827; overflow-wrap: anywhere; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 12px 0 24px; }}
    .summary-card {{ border-left: 6px solid #6b7280; padding: 16px; }}
    .critical {{ border-color: #7f1d1d; }}
    .high {{ border-color: #dc2626; }}
    .medium {{ border-color: #d97706; }}
    .low {{ border-color: #2563eb; }}
    .findings {{ display: grid; gap: 14px; }}
    .finding-card {{ padding: 18px; border: 1px solid #dfe5ee; }}
    .finding-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
    .finding-title {{ margin: 0; font-size: 18px; color: #111827; }}
    .resource {{ margin-top: 4px; color: #5b6577; overflow-wrap: anywhere; }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 5px 10px; color: white; font-size: 12px; font-weight: 700; }}
    .badge.critical {{ background: #7f1d1d; }}
    .badge.high {{ background: #dc2626; }}
    .badge.medium {{ background: #d97706; }}
    .badge.low {{ background: #2563eb; }}
    .demo-flag {{ display: inline-block; margin-top: 10px; padding: 6px 10px; border-radius: 999px; background: #facc15; color: #422006; font-size: 12px; font-weight: 700; }}
    .detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-top: 16px; }}
    .detail {{ border-top: 1px solid #e5e7eb; padding-top: 10px; }}
    .detail span {{ display: block; font-size: 12px; font-weight: 700; color: #5b6577; text-transform: uppercase; margin-bottom: 6px; }}
    code {{ display: block; white-space: pre-wrap; word-break: break-word; background: #f3f6fa; color: #0f172a; padding: 10px; border-radius: 6px; }}
    .empty {{ background: white; color: #047857; border: 1px solid #bbf7d0; border-radius: 8px; padding: 24px; text-align: center; font-weight: 700; }}
    @media (max-width: 640px) {{
      header {{ padding: 24px; }}
      main {{ padding: 18px; }}
      h1 {{ font-size: 26px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>CloudGuard AI Report</h1>
    <p>AWS Security Auditing Tool</p>
    <p>Built by Jayanti Dani</p>
    <p>Version: 1.0.0</p>
    <p>Tech Stack:<br>Python | Boto3 | AWS | Rich | Jinja2</p>
    <p>GitHub:<br><a href="https://github.com/jayantidani/cloudguard-ai.git">https://github.com/jayantidani/cloudguard-ai.git</a></p>
    <span class="demo-flag">DEMO MODE - resource identifiers are masked for screenshots</span>
  </header>
  <main>
    <section class="dashboard">
      <div class="metric"><span>AWS Account ID</span><strong>{escape(display_summary.account_id)}</strong></div>
      <div class="metric"><span>Scan Timestamp</span><strong>{escape(display_summary.scan_timestamp)}</strong></div>
      <div class="metric"><span>Total Findings</span><strong>{display_summary.total_findings}</strong></div>
      <div class="metric"><span>Security Score</span><strong>{display_summary.security_score}/100</strong></div>
    </section>
    <h2>Severity Summary</h2>
    <section class="summary">{summary_cards}</section>
    <h2>Findings</h2>
    <section class="findings">{finding_cards}</section>
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )


def demo_scan_summary(summary: ScanSummary) -> ScanSummary:
    return ScanSummary(
        account_id=DEMO_ACCOUNT_ID,
        scan_timestamp=summary.scan_timestamp,
        total_findings=summary.total_findings,
        security_score=summary.security_score,
    )


def demo_finding(finding: Finding) -> Finding:
    if finding.service == "S3":
        return Finding(
            service=finding.service,
            resource=DEMO_S3_BUCKET,
            severity=finding.severity,
            issue=finding.issue,
            region=finding.region,
            risk_explanation=finding.risk_explanation,
            business_impact=finding.business_impact,
            recommended_fix=finding.recommended_fix,
            aws_cli_remediation=f"aws s3api put-public-access-block --bucket {DEMO_S3_BUCKET} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        )

    if finding.service == "IAM":
        return Finding(
            service=finding.service,
            resource=DEMO_IAM_USER,
            severity=finding.severity,
            issue=finding.issue,
            region=finding.region,
            risk_explanation=finding.risk_explanation,
            business_impact=finding.business_impact,
            recommended_fix=finding.recommended_fix,
            aws_cli_remediation=_sanitize_iam_command(finding.aws_cli_remediation),
        )

    return finding


def _sanitize_iam_command(command: str) -> str:
    parts = command.split()
    sanitized: list[str] = []
    replacement: str | None = None
    for part in parts:
        if replacement is not None:
            sanitized.append(replacement)
            replacement = None
            continue
        sanitized.append(part)
        if part == "--user-name":
            replacement = DEMO_IAM_USER
        elif part == "--access-key-id":
            replacement = DEMO_ACCESS_KEY_ID
    return " ".join(sanitized)


def _finding_card(finding: Finding) -> str:
    severity = escape(finding.severity.lower())
    return f"""<article class="finding-card">
  <div class="finding-top">
    <div>
      <h3 class="finding-title">{escape(finding.service)} - {escape(finding.issue)}</h3>
      <div class="resource">{escape(finding.resource)} | {escape(finding.region)}</div>
    </div>
    <span class="badge {severity}">{escape(finding.severity)}</span>
  </div>
  <div class="detail-grid">
    <div class="detail"><span>Risk</span>{escape(finding.risk_explanation)}</div>
    <div class="detail"><span>Business Impact</span>{escape(finding.business_impact)}</div>
    <div class="detail"><span>Recommended Fix</span>{escape(finding.recommended_fix)}</div>
    <div class="detail"><span>AWS CLI Remediation</span><code>{escape(finding.aws_cli_remediation)}</code></div>
  </div>
</article>"""


if __name__ == "__main__":
    sys.exit(main())
