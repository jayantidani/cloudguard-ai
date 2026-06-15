from __future__ import annotations

import boto3
from botocore.config import Config


def create_session(profile: str | None, region: str | None) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


def client(session: boto3.Session, service: str, region: str | None = None):
    return session.client(
        service,
        region_name=region or session.region_name,
        config=Config(retries={"max_attempts": 10, "mode": "standard"}),
    )
