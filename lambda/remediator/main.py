"""
Auto-remediation Lambda for compliance violations.

Automatically fixes low-risk compliance violations detected by the scanner.
High-risk violations require manual approval via SNS + API Gateway workflow.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError


LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(logging.StreamHandler())


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main handler for auto-remediation.

    Event structure:
    {
      "violation": {
        "resource_id": "arn:aws:s3:::bucket",
        "resource_type": "aws_s3_bucket",
        "control": "SOC2-CC6.1",
        "severity": "CRITICAL",
        "message": "Bucket missing encryption",
        "evidence": {...}
      },
      "auto_remediate": true,  # If false, requires approval
      "approval_token": "uuid"  # Required for manual approval workflow
    }
    """
    session = boto3.Session(region_name=_env("AWS_REGION", "us-east-1"))

    violation = event.get("violation", {})
    auto_remediate = event.get("auto_remediate", False)
    approval_token = event.get("approval_token")

    remediation_id = str(uuid.uuid4())

    # Validate input
    if not violation:
        logger.error("No violation provided in event")
        return {"status": "error", "message": "Missing violation data"}

    resource_type = violation.get("resource_type")
    resource_id = violation.get("resource_id")
    severity = violation.get("severity", "UNKNOWN")

    logger.info(
        "Remediation request: id=%s, resource=%s, type=%s, severity=%s, auto=%s",
        remediation_id, resource_id, resource_type, severity, auto_remediate
    )

    # Check if auto-remediation is allowed for this severity
    if severity in ("CRITICAL", "HIGH") and not approval_token:
        # Require manual approval for critical violations
        return request_approval(session, violation, remediation_id)

    # Route to appropriate remediation handler
    try:
        result = remediate_violation(session, violation, remediation_id)

        # Log remediation action
        log_remediation(session, remediation_id, violation, result)

        return {
            "remediation_id": remediation_id,
            "status": result["status"],
            "message": result["message"],
            "actions": result.get("actions", [])
        }
    except Exception as exc:
        logger.exception("Remediation failed: %s", exc)
        log_remediation(session, remediation_id, violation, {
            "status": "failed",
            "message": str(exc),
            "actions": []
        })
        return {
            "remediation_id": remediation_id,
            "status": "failed",
            "message": str(exc)
        }


def remediate_violation(
    session: boto3.Session,
    violation: Dict[str, Any],
    remediation_id: str
) -> Dict[str, Any]:
    """Route violation to appropriate remediation handler."""
    resource_type = violation.get("resource_type")

    handlers = {
        "aws_s3_bucket": remediate_s3_encryption,
        "aws_db_instance": remediate_rds_security,
        "aws_security_group": remediate_security_group,
        "aws_cloudtrail": remediate_cloudtrail,
    }

    handler = handlers.get(resource_type)
    if not handler:
        return {
            "status": "unsupported",
            "message": f"No remediation handler for {resource_type}",
            "actions": []
        }

    return handler(session, violation, remediation_id)


def remediate_s3_encryption(
    session: boto3.Session,
    violation: Dict[str, Any],
    remediation_id: str
) -> Dict[str, Any]:
    """Enable S3 bucket encryption."""
    s3_client = session.client("s3")

    # Extract bucket name from ARN
    resource_id = violation["resource_id"]
    if resource_id.startswith("arn:aws:s3:::"):
        bucket_name = resource_id.replace("arn:aws:s3:::", "")
    else:
        bucket_name = resource_id

    actions = []

    try:
        # Check current encryption
        try:
            current_enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
            logger.info("Bucket %s already has encryption: %s", bucket_name, current_enc)
            return {
                "status": "already_compliant",
                "message": f"Bucket {bucket_name} already encrypted",
                "actions": []
            }
        except ClientError as e:
            if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                raise

        # Enable AES256 encryption (KMS requires key ARN, using AES256 for simplicity)
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        },
                        "BucketKeyEnabled": True
                    }
                ]
            }
        )

        actions.append({
            "action": "put_bucket_encryption",
            "bucket": bucket_name,
            "algorithm": "AES256",
            "timestamp": _now_iso()
        })

        logger.info("Enabled AES256 encryption for bucket %s", bucket_name)

        return {
            "status": "remediated",
            "message": f"Enabled AES256 encryption for bucket {bucket_name}",
            "actions": actions
        }

    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to remediate S3 bucket %s: %s", bucket_name, exc)
        return {
            "status": "failed",
            "message": f"Failed to enable encryption: {exc}",
            "actions": actions
        }


def remediate_rds_security(
    session: boto3.Session,
    violation: Dict[str, Any],
    remediation_id: str
) -> Dict[str, Any]:
    """Fix RDS security issues (backup retention, public access)."""
    rds_client = session.client("rds")

    resource_id = violation["resource_id"]
    evidence = violation.get("evidence", {})
    control = violation.get("control", "")

    # Extract DB instance identifier from ARN
    if ":" in resource_id:
        db_id = resource_id.split(":")[-1]
    else:
        db_id = resource_id

    actions = []
    modifications = {}

    try:
        # Get current DB instance details
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_id)
        db_instance = response["DBInstances"][0]

        # Fix backup retention if needed (SOC2-A1.2)
        if "A1.2" in control:
            current_retention = db_instance.get("BackupRetentionPeriod", 0)
            min_retention = int(_env("MIN_RDS_BACKUP_DAYS", "7"))

            if current_retention < min_retention:
                modifications["BackupRetentionPeriod"] = min_retention
                actions.append({
                    "action": "set_backup_retention",
                    "from": current_retention,
                    "to": min_retention
                })

        # Fix public accessibility if needed (SOC2-CC6.6)
        if "CC6.6" in control and db_instance.get("PubliclyAccessible"):
            modifications["PubliclyAccessible"] = False
            actions.append({
                "action": "disable_public_access",
                "from": True,
                "to": False
            })

        # Apply modifications
        if modifications:
            rds_client.modify_db_instance(
                DBInstanceIdentifier=db_id,
                **modifications,
                ApplyImmediately=True
            )

            logger.info("Modified RDS instance %s: %s", db_id, modifications)

            return {
                "status": "remediated",
                "message": f"Fixed RDS instance {db_id}",
                "actions": actions
            }
        else:
            return {
                "status": "already_compliant",
                "message": f"RDS instance {db_id} already compliant",
                "actions": []
            }

    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to remediate RDS instance %s: %s", db_id, exc)
        return {
            "status": "failed",
            "message": f"Failed to modify RDS instance: {exc}",
            "actions": actions
        }


def remediate_security_group(
    session: boto3.Session,
    violation: Dict[str, Any],
    remediation_id: str
) -> Dict[str, Any]:
    """
    Remove overly permissive security group rules.

    Note: This is a sensitive operation and should require approval for production.
    """
    ec2_client = session.client("ec2")

    resource_id = violation["resource_id"]
    evidence = violation.get("evidence", {})

    # Extract security group ID and port
    if ":" in resource_id:
        sg_id, port_str = resource_id.split(":")
        port = int(port_str)
    else:
        return {
            "status": "failed",
            "message": "Invalid resource_id format for security group",
            "actions": []
        }

    actions = []

    try:
        # Get security group details
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg = response["SecurityGroups"][0]

        # Find and remove 0.0.0.0/0 rule for this port
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            # Check if this rule covers our port
            if from_port is not None and to_port is not None:
                if from_port <= port <= to_port:
                    # Check for 0.0.0.0/0
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            # Revoke this rule
                            ec2_client.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions=[rule]
                            )

                            actions.append({
                                "action": "revoke_ingress_rule",
                                "group_id": sg_id,
                                "port": port,
                                "cidr": "0.0.0.0/0",
                                "timestamp": _now_iso()
                            })

                            logger.warning(
                                "Revoked 0.0.0.0/0 ingress rule for port %d in SG %s",
                                port, sg_id
                            )

        if actions:
            return {
                "status": "remediated",
                "message": f"Removed public access rule for port {port} in {sg_id}",
                "actions": actions
            }
        else:
            return {
                "status": "already_compliant",
                "message": f"No public access rule found for port {port}",
                "actions": []
            }

    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to remediate security group %s: %s", sg_id, exc)
        return {
            "status": "failed",
            "message": f"Failed to modify security group: {exc}",
            "actions": actions
        }


def remediate_cloudtrail(
    session: boto3.Session,
    violation: Dict[str, Any],
    remediation_id: str
) -> Dict[str, Any]:
    """Enable or update CloudTrail configuration."""
    cloudtrail_client = session.client("cloudtrail")

    resource_id = violation["resource_id"]
    control = violation.get("control", "")
    evidence = violation.get("evidence", {})

    actions = []

    try:
        # Check if CloudTrail exists
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False)
        trail_list = trails.get("trailList", [])

        if not trail_list:
            # Create new CloudTrail
            trail_name = "compliance-enforcer-trail"
            bucket_name = _env("CLOUDTRAIL_BUCKET", "compliance-cloudtrail-logs")

            # Note: In production, bucket should be pre-created with proper policies
            cloudtrail_client.create_trail(
                Name=trail_name,
                S3BucketName=bucket_name,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                # KmsKeyId would go here if available
            )

            # Start logging
            cloudtrail_client.start_logging(Name=trail_name)

            actions.append({
                "action": "create_cloudtrail",
                "trail_name": trail_name,
                "multi_region": True,
                "log_validation": True
            })

            logger.info("Created new CloudTrail: %s", trail_name)

            return {
                "status": "remediated",
                "message": f"Created multi-region CloudTrail {trail_name}",
                "actions": actions
            }
        else:
            # Update existing trail
            trail = trail_list[0]
            trail_name = trail["Name"]
            trail_arn = trail.get("TrailARN", trail_name)

            updates = {}

            # Enable multi-region if needed
            if not trail.get("IsMultiRegionTrail"):
                updates["IsMultiRegionTrail"] = True
                actions.append({"action": "enable_multi_region"})

            # Enable log file validation if needed
            if not trail.get("LogFileValidationEnabled"):
                updates["EnableLogFileValidation"] = True
                actions.append({"action": "enable_log_validation"})

            if updates:
                cloudtrail_client.update_trail(Name=trail_name, **updates)

                logger.info("Updated CloudTrail %s: %s", trail_name, updates)

                return {
                    "status": "remediated",
                    "message": f"Updated CloudTrail {trail_name}",
                    "actions": actions
                }
            else:
                return {
                    "status": "already_compliant",
                    "message": f"CloudTrail {trail_name} already compliant",
                    "actions": []
                }

    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to remediate CloudTrail: %s", exc)
        return {
            "status": "failed",
            "message": f"Failed to configure CloudTrail: {exc}",
            "actions": actions
        }


def request_approval(
    session: boto3.Session,
    violation: Dict[str, Any],
    remediation_id: str
) -> Dict[str, Any]:
    """
    Request manual approval for high-risk remediation.

    Sends SNS notification with approval/deny links.
    """
    sns_client = session.client("sns")
    sns_topic_arn = _env("APPROVAL_SNS_TOPIC")

    if not sns_topic_arn:
        logger.warning("No APPROVAL_SNS_TOPIC configured, skipping approval request")
        return {
            "status": "approval_required",
            "message": "Manual approval required but no SNS topic configured",
            "remediation_id": remediation_id
        }

    # Generate approval token
    approval_token = str(uuid.uuid4())

    # API Gateway URLs for approval/deny (would be configured via env vars)
    api_base = _env("APPROVAL_API_BASE", "https://api.example.com/remediation")
    approve_url = f"{api_base}/{remediation_id}/approve?token={approval_token}"
    deny_url = f"{api_base}/{remediation_id}/deny?token={approval_token}"

    message = f"""
🚨 COMPLIANCE REMEDIATION APPROVAL REQUIRED

Remediation ID: {remediation_id}
Resource: {violation.get('resource_id')}
Resource Type: {violation.get('resource_type')}
Severity: {violation.get('severity')}
Control: {violation.get('control')}
Violation: {violation.get('message')}

Proposed Remediation:
{violation.get('remediation', 'See remediation handler')}

ACTIONS:
✅ Approve: {approve_url}
❌ Deny: {deny_url}

This approval request expires in 24 hours.
    """

    try:
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=f"🚨 Remediation Approval Required: {violation.get('resource_type')}",
            Message=message
        )

        logger.info("Sent approval request for remediation %s to SNS", remediation_id)

        # Store approval request in DynamoDB (for tracking)
        store_approval_request(session, remediation_id, violation, approval_token)

        return {
            "status": "approval_required",
            "message": "Manual approval requested via SNS",
            "remediation_id": remediation_id,
            "approval_token": approval_token
        }

    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to send approval request: %s", exc)
        return {
            "status": "failed",
            "message": f"Failed to request approval: {exc}",
            "remediation_id": remediation_id
        }


def store_approval_request(
    session: boto3.Session,
    remediation_id: str,
    violation: Dict[str, Any],
    approval_token: str
) -> None:
    """Store approval request in DynamoDB for tracking."""
    table_name = _env("REMEDIATION_TABLE")
    if not table_name:
        logger.warning("No REMEDIATION_TABLE configured")
        return

    dynamodb = session.resource("dynamodb")
    table = dynamodb.Table(table_name)

    try:
        table.put_item(
            Item={
                "pk": f"REMEDIATION#{remediation_id}",
                "sk": "APPROVAL",
                "violation": json.dumps(violation),
                "approval_token": approval_token,
                "status": "pending",
                "requested_at": _now_iso(),
                "expires_at": (
                    datetime.datetime.utcnow() + datetime.timedelta(hours=24)
                ).isoformat(),
            }
        )
        logger.info("Stored approval request for %s in DynamoDB", remediation_id)
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to store approval request: %s", exc)


def log_remediation(
    session: boto3.Session,
    remediation_id: str,
    violation: Dict[str, Any],
    result: Dict[str, Any]
) -> None:
    """Log remediation action to DynamoDB for audit trail."""
    table_name = _env("REMEDIATION_TABLE")
    if not table_name:
        logger.warning("No REMEDIATION_TABLE configured")
        return

    dynamodb = session.resource("dynamodb")
    table = dynamodb.Table(table_name)

    try:
        table.put_item(
            Item={
                "pk": f"REMEDIATION#{remediation_id}",
                "sk": _now_iso(),
                "resource_id": violation.get("resource_id"),
                "resource_type": violation.get("resource_type"),
                "control": violation.get("control"),
                "severity": violation.get("severity"),
                "status": result.get("status"),
                "message": result.get("message"),
                "actions": json.dumps(result.get("actions", [])),
                "timestamp": _now_iso(),
            }
        )
        logger.info("Logged remediation %s to DynamoDB", remediation_id)
    except (ClientError, BotoCoreError) as exc:
        logger.exception("Failed to log remediation: %s", exc)
