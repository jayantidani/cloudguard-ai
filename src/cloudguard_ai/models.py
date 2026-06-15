from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    service: str
    resource: str
    severity: str
    issue: str
    region: str
    risk_explanation: str
    business_impact: str
    recommended_fix: str
    aws_cli_remediation: str


@dataclass(frozen=True)
class ScanSummary:
    account_id: str
    scan_timestamp: str
    total_findings: int
    security_score: int
