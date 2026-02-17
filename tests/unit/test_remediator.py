"""
Unit tests for Lambda remediator function.

Uses moto to mock AWS services.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest

# Add lambda remediator directory to path
remediator_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../lambda/remediator"))
if remediator_path not in sys.path:
    sys.path.insert(0, remediator_path)

# Import remediator module
import importlib.util
spec = importlib.util.spec_from_file_location("remediator_main", os.path.join(remediator_path, "main.py"))
remediator_main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remediator_main)

remediate_s3_encryption = remediator_main.remediate_s3_encryption
remediate_rds_security = remediator_main.remediate_rds_security
remediate_security_group = remediator_main.remediate_security_group
remediate_cloudtrail = remediator_main.remediate_cloudtrail
request_approval = remediator_main.request_approval


class TestS3Remediation:
    """Tests for S3 encryption remediation."""

    @patch("boto3.Session.client")
    def test_remediate_s3_bucket_missing_encryption(self, mock_client):
        """Test remediating S3 bucket without encryption."""
        s3_mock = MagicMock()
        mock_client.return_value = s3_mock
        session_mock = MagicMock()
        session_mock.client.return_value = s3_mock

        # Bucket has no encryption
        from botocore.exceptions import ClientError
        s3_mock.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            "GetBucketEncryption"
        )

        violation = {
            "resource_id": "arn:aws:s3:::test-bucket",
            "resource_type": "aws_s3_bucket",
            "control": "SOC2-CC6.1",
        }

        result = remediate_s3_encryption(session_mock, violation, "remediation-1")

        assert result["status"] == "remediated"
        assert "test-bucket" in result["message"]
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action"] == "put_bucket_encryption"
        assert result["actions"][0]["algorithm"] == "AES256"

        # Verify put_bucket_encryption was called
        s3_mock.put_bucket_encryption.assert_called_once()

    @patch("boto3.Session.client")
    def test_remediate_s3_bucket_already_encrypted(self, mock_client):
        """Test S3 bucket that already has encryption."""
        s3_mock = MagicMock()
        mock_client.return_value = s3_mock
        session_mock = MagicMock()
        session_mock.client.return_value = s3_mock

        # Bucket already encrypted
        s3_mock.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        violation = {
            "resource_id": "arn:aws:s3:::encrypted-bucket",
            "resource_type": "aws_s3_bucket",
        }

        result = remediate_s3_encryption(session_mock, violation, "remediation-2")

        assert result["status"] == "already_compliant"
        assert len(result["actions"]) == 0

        # put_bucket_encryption should NOT be called
        s3_mock.put_bucket_encryption.assert_not_called()


class TestRDSRemediation:
    """Tests for RDS security remediation."""

    @patch("boto3.Session.client")
    def test_remediate_rds_backup_retention(self, mock_client):
        """Test fixing RDS backup retention."""
        rds_mock = MagicMock()
        mock_client.return_value = rds_mock
        session_mock = MagicMock()
        session_mock.client.return_value = rds_mock

        rds_mock.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "test-db",
                    "BackupRetentionPeriod": 3,
                    "PubliclyAccessible": False,
                }
            ]
        }

        violation = {
            "resource_id": "arn:aws:rds:us-east-1:123456789012:db:test-db",
            "resource_type": "aws_db_instance",
            "control": "SOC2-A1.2",
            "evidence": {},
        }

        with patch.dict(os.environ, {"MIN_RDS_BACKUP_DAYS": "7"}):
            result = remediate_rds_security(session_mock, violation, "remediation-3")

        assert result["status"] == "remediated"
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action"] == "set_backup_retention"
        assert result["actions"][0]["from"] == 3
        assert result["actions"][0]["to"] == 7

        # Verify modify_db_instance was called
        rds_mock.modify_db_instance.assert_called_once_with(
            DBInstanceIdentifier="test-db",
            BackupRetentionPeriod=7,
            ApplyImmediately=True,
        )

    @patch("boto3.Session.client")
    def test_remediate_rds_public_access(self, mock_client):
        """Test disabling RDS public access."""
        rds_mock = MagicMock()
        mock_client.return_value = rds_mock
        session_mock = MagicMock()
        session_mock.client.return_value = rds_mock

        rds_mock.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "public-db",
                    "BackupRetentionPeriod": 7,
                    "PubliclyAccessible": True,
                }
            ]
        }

        violation = {
            "resource_id": "arn:aws:rds:us-east-1:123456789012:db:public-db",
            "resource_type": "aws_db_instance",
            "control": "SOC2-CC6.6",
            "evidence": {},
        }

        result = remediate_rds_security(session_mock, violation, "remediation-4")

        assert result["status"] == "remediated"
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action"] == "disable_public_access"

        # Verify modify_db_instance was called
        rds_mock.modify_db_instance.assert_called_once_with(
            DBInstanceIdentifier="public-db",
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )


class TestSecurityGroupRemediation:
    """Tests for Security Group remediation."""

    @patch("boto3.Session.client")
    def test_remediate_security_group_public_ssh(self, mock_client):
        """Test removing public SSH access from security group."""
        ec2_mock = MagicMock()
        mock_client.return_value = ec2_mock
        session_mock = MagicMock()
        session_mock.client.return_value = ec2_mock

        ec2_mock.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-12345",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }

        violation = {
            "resource_id": "sg-12345:22",
            "resource_type": "aws_security_group",
            "control": "SOC2-CC6.6",
            "evidence": {"group_id": "sg-12345", "port": 22},
        }

        result = remediate_security_group(session_mock, violation, "remediation-5")

        assert result["status"] == "remediated"
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action"] == "revoke_ingress_rule"
        assert result["actions"][0]["port"] == 22

        # Verify revoke_security_group_ingress was called
        ec2_mock.revoke_security_group_ingress.assert_called_once()


class TestCloudTrailRemediation:
    """Tests for CloudTrail remediation."""

    @patch("boto3.Session.client")
    def test_remediate_cloudtrail_create(self, mock_client):
        """Test creating CloudTrail when none exists."""
        ct_mock = MagicMock()
        mock_client.return_value = ct_mock
        session_mock = MagicMock()
        session_mock.client.return_value = ct_mock

        # No existing trails
        ct_mock.describe_trails.return_value = {"trailList": []}

        violation = {
            "resource_id": "cloudtrail",
            "resource_type": "aws_cloudtrail",
            "control": "SOC2-CC7.2",
            "evidence": {},
        }

        with patch.dict(os.environ, {"CLOUDTRAIL_BUCKET": "cloudtrail-logs"}):
            result = remediate_cloudtrail(session_mock, violation, "remediation-6")

        assert result["status"] == "remediated"
        assert len(result["actions"]) == 1
        assert result["actions"][0]["action"] == "create_cloudtrail"
        assert result["actions"][0]["multi_region"] is True
        assert result["actions"][0]["log_validation"] is True

        # Verify create_trail and start_logging were called
        ct_mock.create_trail.assert_called_once()
        ct_mock.start_logging.assert_called_once()

    @patch("boto3.Session.client")
    def test_remediate_cloudtrail_update(self, mock_client):
        """Test updating existing CloudTrail."""
        ct_mock = MagicMock()
        mock_client.return_value = ct_mock
        session_mock = MagicMock()
        session_mock.client.return_value = ct_mock

        # Trail exists but not multi-region
        ct_mock.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "my-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
                    "IsMultiRegionTrail": False,
                    "LogFileValidationEnabled": False,
                }
            ]
        }

        violation = {
            "resource_id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
            "resource_type": "aws_cloudtrail",
            "control": "SOC2-CC7.2",
            "evidence": {},
        }

        result = remediate_cloudtrail(session_mock, violation, "remediation-7")

        assert result["status"] == "remediated"
        assert len(result["actions"]) == 2
        assert any(a["action"] == "enable_multi_region" for a in result["actions"])
        assert any(a["action"] == "enable_log_validation" for a in result["actions"])

        # Verify update_trail was called
        ct_mock.update_trail.assert_called_once()


class TestApprovalWorkflow:
    """Tests for approval workflow."""

    @patch("boto3.Session.client")
    @patch("boto3.Session.resource")
    def test_request_approval_sends_sns(self, mock_resource, mock_client):
        """Test that approval request sends SNS notification."""
        sns_mock = MagicMock()
        mock_client.return_value = sns_mock
        session_mock = MagicMock()
        session_mock.client.return_value = sns_mock

        dynamodb_resource_mock = MagicMock()
        mock_resource.return_value = dynamodb_resource_mock

        table_mock = MagicMock()
        dynamodb_resource_mock.Table.return_value = table_mock

        violation = {
            "resource_id": "sg-12345:22",
            "resource_type": "aws_security_group",
            "control": "SOC2-CC6.6",
            "severity": "CRITICAL",
            "message": "Public SSH access",
            "remediation": "Restrict to corporate CIDR",
        }

        with patch.dict(os.environ, {
            "APPROVAL_SNS_TOPIC": "arn:aws:sns:us-east-1:123456789012:approvals",
            "REMEDIATION_TABLE": "compliance-remediations",
        }):
            result = request_approval(session_mock, violation, "remediation-8")

        assert result["status"] == "approval_required"
        assert "approval_token" in result

        # Verify SNS publish was called
        sns_mock.publish.assert_called_once()
        call_args = sns_mock.publish.call_args
        assert "TopicArn" in call_args[1]
        assert "Message" in call_args[1]
        assert "APPROVAL REQUIRED" in call_args[1]["Message"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
