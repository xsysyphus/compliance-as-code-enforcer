"""
Runtime compliance scanner.

Scans AWS resources (S3, RDS, Security Groups, CloudTrail) and records
pass/fail findings aligned with the SOC2 policies used in pre-deploy OPA checks.
Results are persisted to DynamoDB for history and to S3 as evidence.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError, BotoCoreError


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(logging.StreamHandler())


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


def _env(name: str, default: str) -> str:
    return os.getenv(name, default)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    session = boto3.Session(region_name=_env("SCAN_REGION", _env("AWS_REGION", "us-east-1")))
    run_id = str(uuid.uuid4())

    table_name = _env("DYNAMO_TABLE", "")
    evidence_bucket = _env("EVIDENCE_BUCKET", "")
    min_backup_days = int(_env("MIN_RDS_BACKUP_DAYS", "7"))

    results: List[Dict[str, Any]] = []

    try:
        s3_client = session.client("s3")
        rds_client = session.client("rds")
        ec2_client = session.client("ec2")
        cloudtrail_client = session.client("cloudtrail")
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to create AWS clients: %s", exc)
        raise

    results.extend(check_s3_encryption(s3_client))
    results.extend(check_rds_backup_and_encryption(rds_client, min_backup_days))
    results.extend(check_security_groups(ec2_client))
    results.extend(check_cloudtrail(cloudtrail_client))

    summary = summarize(results)
    logger.info("Scan run %s - resources: %d, failures: %d", run_id, summary["resources"], summary["failures"])

    # Structured log for CloudWatch metrics/alarms
    logger.info(
        json.dumps(
            {
                "event": "compliance_scan_summary",
                "run_id": run_id,
                **summary,
            }
        )
    )

    if table_name:
        persist_to_dynamodb(session, table_name, run_id, results)
    else:
        logger.warning("DYNAMO_TABLE not set; skipping DynamoDB persistence.")

    if evidence_bucket:
        persist_to_s3(session, evidence_bucket, run_id, results)
    else:
        logger.warning("EVIDENCE_BUCKET not set; skipping S3 evidence.")

    return {"run_id": run_id, **summary}


def check_s3_encryption(s3_client) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to list S3 buckets: %s", exc)
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        resource_id = f"arn:aws:s3:::{name}"
        status = "PASS"
        severity = "INFO"
        message = "S3 bucket encrypted at rest."
        evidence: Dict[str, Any] = {"bucket": name}

        try:
            enc = s3_client.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
            kms_key = rules[0]["ApplyServerSideEncryptionByDefault"].get("KMSMasterKeyID")
            evidence.update({"algorithm": algo, "kms_key": kms_key})

            if algo not in ("AES256", "aws:kms"):
                status = "FAIL"
                severity = "CRITICAL"
                message = f"Unsupported encryption algorithm {algo}."
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                status = "FAIL"
                severity = "CRITICAL"
                message = "Bucket missing server-side encryption."
            else:
                logger.warning("Error checking bucket %s encryption: %s", name, exc)
                status = "FAIL"
                severity = "HIGH"
                message = "Could not verify encryption."

        findings.append(
            make_finding(
                resource_id=resource_id,
                resource_type="aws_s3_bucket",
                control="SOC2-CC6.1/CC6.7",
                status=status,
                severity=severity,
                message=message,
                remediation="Enable SSE-KMS or AES256 via bucket encryption settings.",
                evidence=evidence,
            )
        )

    return findings


def check_rds_backup_and_encryption(rds_client, min_backup_days: int) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    paginator = rds_client.get_paginator("describe_db_instances")

    try:
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                resource_arn = db.get("DBInstanceArn", db["DBInstanceIdentifier"])
                evidence = {
                    "engine": db.get("Engine"),
                    "backup_retention_period": db.get("BackupRetentionPeriod"),
                    "publicly_accessible": db.get("PubliclyAccessible"),
                    "storage_encrypted": db.get("StorageEncrypted"),
                }

                # Encryption check
                findings.append(
                    make_finding(
                        resource_id=resource_arn,
                        resource_type="aws_db_instance",
                        control="SOC2-CC6.7",
                        status="PASS" if db.get("StorageEncrypted") else "FAIL",
                        severity="CRITICAL" if not db.get("StorageEncrypted") else "INFO",
                        message="RDS storage encryption enabled."
                        if db.get("StorageEncrypted")
                        else "RDS instance missing storage encryption.",
                        remediation="Set storage_encrypted = true and use KMS key.",
                        evidence=evidence,
                    )
                )

                # Backup retention check
                retention = db.get("BackupRetentionPeriod") or 0
                findings.append(
                    make_finding(
                        resource_id=resource_arn,
                        resource_type="aws_db_instance",
                        control="SOC2-A1.2",
                        status="PASS" if retention >= min_backup_days else "FAIL",
                        severity="HIGH" if retention < min_backup_days else "INFO",
                        message=f"Backup retention is {retention} days.",
                        remediation=f"Set backup_retention_period >= {min_backup_days}.",
                        evidence=evidence,
                    )
                )

                # Public exposure check
                findings.append(
                    make_finding(
                        resource_id=resource_arn,
                        resource_type="aws_db_instance",
                        control="SOC2-CC6.6",
                        status="PASS" if not db.get("PubliclyAccessible") else "FAIL",
                        severity="CRITICAL" if db.get("PubliclyAccessible") else "INFO",
                        message="RDS not publicly accessible."
                        if not db.get("PubliclyAccessible")
                        else "RDS instance is publicly accessible.",
                        remediation="Set publicly_accessible = false and place in private subnets.",
                        evidence=evidence,
                    )
                )
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to describe RDS instances: %s", exc)

    return findings


def check_security_groups(ec2_client) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    critical_ports = {22, 3389}
    database_ports = {3306, 5432}
    try:
        response = ec2_client.describe_security_groups()
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to describe security groups: %s", exc)
        return findings

    for sg in response.get("SecurityGroups", []):
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "")
        for rule in sg.get("IpPermissions", []):
            cidrs = rule.get("IpRanges", [])
            ports = expand_ports(rule)

            if any(c.get("CidrIp") == "0.0.0.0/0" for c in cidrs):
                # Admin ports
                for port in ports:
                    if port in critical_ports:
                        findings.append(
                            make_finding(
                                resource_id=f"{sg_id}:{port}",
                                resource_type="aws_security_group",
                                control="SOC2-CC6.6",
                                status="FAIL",
                                severity="CRITICAL",
                                message=f"Security group {sg_name or sg_id} exposes admin port {port} to 0.0.0.0/0.",
                                remediation="Restrict to corporate CIDR or use SSM Session Manager.",
                                evidence={"group_id": sg_id, "port": port},
                            )
                        )
                    if port in database_ports:
                        findings.append(
                            make_finding(
                                resource_id=f"{sg_id}:{port}",
                                resource_type="aws_security_group",
                                control="SOC2-CC6.6",
                                status="FAIL",
                                severity="CRITICAL",
                                message=f"Security group {sg_name or sg_id} exposes database port {port} to 0.0.0.0/0.",
                                remediation="Allow DB access only from app/security groups, not the internet.",
                                evidence={"group_id": sg_id, "port": port},
                            )
                        )

    return findings


def check_cloudtrail(cloudtrail_client) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to describe CloudTrails: %s", exc)
        return findings

    if not trails:
        findings.append(
            make_finding(
                resource_id="cloudtrail",
                resource_type="aws_cloudtrail",
                control="SOC2-CC7.2/CC7.3",
                status="FAIL",
                severity="CRITICAL",
                message="No CloudTrail trails configured.",
                remediation="Create multi-region CloudTrail with log validation and SSE-KMS.",
                evidence={},
            )
        )
        return findings

    for trail in trails:
        resource_id = trail.get("TrailARN", trail.get("Name"))
        is_multi_region = trail.get("IsMultiRegionTrail", False)
        log_validation = trail.get("LogFileValidationEnabled", False)
        kms_key = trail.get("KmsKeyId")

        evidence = {
            "is_multi_region": is_multi_region,
            "log_file_validation": log_validation,
            "kms_key": kms_key,
        }

        # Multi-region requirement
        findings.append(
            make_finding(
                resource_id=resource_id,
                resource_type="aws_cloudtrail",
                control="SOC2-CC7.2/CC7.3",
                status="PASS" if is_multi_region else "FAIL",
                severity="CRITICAL" if not is_multi_region else "INFO",
                message="CloudTrail multi-region enabled."
                if is_multi_region
                else "CloudTrail not multi-region.",
                remediation="Enable is_multi_region_trail for complete coverage.",
                evidence=evidence,
            )
        )

        # Log validation
        findings.append(
            make_finding(
                resource_id=resource_id,
                resource_type="aws_cloudtrail",
                control="SOC2-CC7.2",
                status="PASS" if log_validation else "FAIL",
                severity="HIGH" if not log_validation else "INFO",
                message="CloudTrail log file validation enabled."
                if log_validation
                else "CloudTrail log file validation disabled.",
                remediation="Enable log_file_validation.",
                evidence=evidence,
            )
        )

        # Encryption
        findings.append(
            make_finding(
                resource_id=resource_id,
                resource_type="aws_cloudtrail",
                control="SOC2-CC6.7",
                status="PASS" if kms_key else "FAIL",
                severity="CRITICAL" if not kms_key else "INFO",
                message="CloudTrail logs encrypted with KMS."
                if kms_key
                else "CloudTrail logs not using KMS encryption.",
                remediation="Specify kms_key_id for CloudTrail.",
                evidence=evidence,
            )
        )

    return findings


def expand_ports(rule: Dict[str, Any]) -> List[int]:
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")
    if from_port is None or to_port is None:
        return []
    if from_port == to_port:
        return [from_port]
    return list(range(from_port, to_port + 1))


def make_finding(
    *,
    resource_id: str,
    resource_type: str,
    control: str,
    status: str,
    severity: str,
    message: str,
    remediation: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "resource_id": resource_id,
        "resource_type": resource_type,
        "control": control,
        "status": status,
        "severity": severity,
        "message": message,
        "remediation": remediation,
        "evidence": evidence,
        "timestamp": _now_iso(),
    }


def summarize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    resources = len({f["resource_id"] for f in findings})
    failures = len([f for f in findings if f["status"] == "FAIL"])
    critical = len([f for f in findings if f["severity"] == "CRITICAL"])
    return {"resources": resources, "failures": failures, "critical": critical}


def persist_to_dynamodb(session, table_name: str, run_id: str, findings: List[Dict[str, Any]]) -> None:
    dynamodb = session.resource("dynamodb")
    table = dynamodb.Table(table_name)
    with table.batch_writer(overwrite_by_pkeys=["pk", "sk"]) as batch:
        for item in findings:
            batch.put_item(
                Item={
                    "pk": f"RUN#{run_id}",
                    "sk": item["resource_id"],
                    "status": item["status"],
                    "severity": item["severity"],
                    "control": item["control"],
                    "message": item["message"],
                    "remediation": item["remediation"],
                    "evidence": json.dumps(item["evidence"]),
                    "timestamp": item["timestamp"],
                }
            )
    logger.info("Persisted %d findings to DynamoDB table %s", len(findings), table_name)


def persist_to_s3(session, bucket: str, run_id: str, findings: List[Dict[str, Any]]) -> None:
    s3 = session.client("s3")
    key = f"scans/{datetime.datetime.utcnow().strftime('%Y/%m/%d')}/scan-{run_id}.json"
    try:
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(findings, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        logger.info("Stored evidence in s3://%s/%s", bucket, key)
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to write evidence to S3: %s", exc)
