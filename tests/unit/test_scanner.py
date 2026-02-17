"""
Unit tests for Lambda scanner function.

Uses moto to mock AWS services.
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch
from importlib import import_module

import pytest

# Add lambda scanner directory to path
scanner_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../lambda/scanner"))
if scanner_path not in sys.path:
    sys.path.insert(0, scanner_path)

# Import scanner module
import importlib.util
spec = importlib.util.spec_from_file_location("scanner_main", os.path.join(scanner_path, "main.py"))
scanner_main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner_main)

check_s3_encryption = scanner_main.check_s3_encryption
check_rds_backup_and_encryption = scanner_main.check_rds_backup_and_encryption
check_security_groups = scanner_main.check_security_groups
check_cloudtrail = scanner_main.check_cloudtrail
expand_ports = scanner_main.expand_ports
make_finding = scanner_main.make_finding
summarize = scanner_main.summarize


class TestS3Encryption:
    """Tests for S3 encryption checks."""

    @patch("boto3.Session.client")
    def test_s3_bucket_with_encryption(self, mock_client):
        """Test S3 bucket that already has encryption enabled."""
        s3_mock = MagicMock()
        mock_client.return_value = s3_mock

        s3_mock.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }

        s3_mock.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }

        findings = check_s3_encryption(s3_mock)

        assert len(findings) == 1
        assert findings[0]["status"] == "PASS"
        assert findings[0]["severity"] == "INFO"
        assert findings[0]["control"] == "SOC2-CC6.1/CC6.7"

    @patch("boto3.Session.client")
    def test_s3_bucket_without_encryption(self, mock_client):
        """Test S3 bucket missing encryption."""
        s3_mock = MagicMock()
        mock_client.return_value = s3_mock

        s3_mock.list_buckets.return_value = {
            "Buckets": [{"Name": "test-bucket"}]
        }

        from botocore.exceptions import ClientError
        s3_mock.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            "GetBucketEncryption"
        )

        findings = check_s3_encryption(s3_mock)

        assert len(findings) == 1
        assert findings[0]["status"] == "FAIL"
        assert findings[0]["severity"] == "CRITICAL"
        assert "missing server-side encryption" in findings[0]["message"].lower()


class TestRDSChecks:
    """Tests for RDS security checks."""

    @patch("boto3.Session.client")
    def test_rds_compliant_instance(self, mock_client):
        """Test RDS instance that meets all requirements."""
        rds_mock = MagicMock()
        mock_client.return_value = rds_mock

        paginator_mock = MagicMock()
        rds_mock.get_paginator.return_value = paginator_mock

        paginator_mock.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "test-db",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-db",
                        "Engine": "postgres",
                        "BackupRetentionPeriod": 7,
                        "PubliclyAccessible": False,
                        "StorageEncrypted": True,
                    }
                ]
            }
        ]

        findings = check_rds_backup_and_encryption(rds_mock, min_backup_days=7)

        # Should have 3 findings (encryption, backup, public access) - all PASS
        assert len(findings) == 3
        assert all(f["status"] == "PASS" for f in findings)

    @patch("boto3.Session.client")
    def test_rds_non_compliant_instance(self, mock_client):
        """Test RDS instance with violations."""
        rds_mock = MagicMock()
        mock_client.return_value = rds_mock

        paginator_mock = MagicMock()
        rds_mock.get_paginator.return_value = paginator_mock

        paginator_mock.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "bad-db",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:bad-db",
                        "Engine": "mysql",
                        "BackupRetentionPeriod": 3,  # Less than 7
                        "PubliclyAccessible": True,  # Public
                        "StorageEncrypted": False,  # Not encrypted
                    }
                ]
            }
        ]

        findings = check_rds_backup_and_encryption(rds_mock, min_backup_days=7)

        # Should have 3 failures
        assert len(findings) == 3
        assert all(f["status"] == "FAIL" for f in findings)

        # Check severities
        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities  # Encryption and public access
        assert "HIGH" in severities  # Backup retention


class TestSecurityGroups:
    """Tests for Security Group checks."""

    @patch("boto3.Session.client")
    def test_security_group_with_public_ssh(self, mock_client):
        """Test security group with 0.0.0.0/0 on port 22."""
        ec2_mock = MagicMock()
        mock_client.return_value = ec2_mock

        ec2_mock.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-12345",
                    "GroupName": "bad-sg",
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

        findings = check_security_groups(ec2_mock)

        assert len(findings) >= 1
        assert findings[0]["status"] == "FAIL"
        assert findings[0]["severity"] == "CRITICAL"
        assert "22" in findings[0]["message"]

    @patch("boto3.Session.client")
    def test_security_group_restricted(self, mock_client):
        """Test security group with restricted access."""
        ec2_mock = MagicMock()
        mock_client.return_value = ec2_mock

        ec2_mock.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-67890",
                    "GroupName": "good-sg",
                    "IpPermissions": [
                        {
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpProtocol": "tcp",
                            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # Private CIDR
                        }
                    ],
                }
            ]
        }

        findings = check_security_groups(ec2_mock)

        # Should have no findings (no violations)
        assert len(findings) == 0


class TestCloudTrail:
    """Tests for CloudTrail checks."""

    @patch("boto3.Session.client")
    def test_no_cloudtrail(self, mock_client):
        """Test when no CloudTrail is configured."""
        ct_mock = MagicMock()
        mock_client.return_value = ct_mock

        ct_mock.describe_trails.return_value = {"trailList": []}

        findings = check_cloudtrail(ct_mock)

        assert len(findings) == 1
        assert findings[0]["status"] == "FAIL"
        assert findings[0]["severity"] == "CRITICAL"
        assert "no cloudtrail" in findings[0]["message"].lower()

    @patch("boto3.Session.client")
    def test_compliant_cloudtrail(self, mock_client):
        """Test properly configured CloudTrail."""
        ct_mock = MagicMock()
        mock_client.return_value = ct_mock

        ct_mock.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "my-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345",
                }
            ]
        }

        findings = check_cloudtrail(ct_mock)

        # Should have 3 findings (multi-region, validation, encryption) - all PASS
        assert len(findings) == 3
        assert all(f["status"] == "PASS" for f in findings)

    @patch("boto3.Session.client")
    def test_non_compliant_cloudtrail(self, mock_client):
        """Test CloudTrail with missing features."""
        ct_mock = MagicMock()
        mock_client.return_value = ct_mock

        ct_mock.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "bad-trail",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/bad-trail",
                    "IsMultiRegionTrail": False,  # Not multi-region
                    "LogFileValidationEnabled": False,  # No validation
                    "KmsKeyId": None,  # No encryption
                }
            ]
        }

        findings = check_cloudtrail(ct_mock)

        # Should have 3 failures
        assert len(findings) == 3
        assert all(f["status"] == "FAIL" for f in findings)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_expand_ports_single(self):
        """Test expanding a single port."""
        rule = {"FromPort": 22, "ToPort": 22}
        ports = expand_ports(rule)
        assert ports == [22]

    def test_expand_ports_range(self):
        """Test expanding a port range."""
        rule = {"FromPort": 80, "ToPort": 82}
        ports = expand_ports(rule)
        assert ports == [80, 81, 82]

    def test_expand_ports_missing(self):
        """Test expanding ports when FromPort/ToPort missing."""
        rule = {}
        ports = expand_ports(rule)
        assert ports == []

    def test_make_finding(self):
        """Test creating a finding."""
        finding = make_finding(
            resource_id="arn:aws:s3:::test",
            resource_type="aws_s3_bucket",
            control="SOC2-CC6.1",
            status="FAIL",
            severity="CRITICAL",
            message="Test message",
            remediation="Test remediation",
            evidence={"key": "value"},
        )

        assert finding["resource_id"] == "arn:aws:s3:::test"
        assert finding["resource_type"] == "aws_s3_bucket"
        assert finding["control"] == "SOC2-CC6.1"
        assert finding["status"] == "FAIL"
        assert finding["severity"] == "CRITICAL"
        assert finding["message"] == "Test message"
        assert finding["remediation"] == "Test remediation"
        assert finding["evidence"] == {"key": "value"}
        assert "id" in finding
        assert "timestamp" in finding

    def test_summarize(self):
        """Test summarizing findings."""
        findings = [
            {
                "id": "1",
                "resource_id": "arn:aws:s3:::bucket1",
                "status": "FAIL",
                "severity": "CRITICAL",
            },
            {
                "id": "2",
                "resource_id": "arn:aws:s3:::bucket2",
                "status": "PASS",
                "severity": "INFO",
            },
            {
                "id": "3",
                "resource_id": "arn:aws:s3:::bucket1",  # Same resource
                "status": "FAIL",
                "severity": "HIGH",
            },
        ]

        summary = summarize(findings)

        assert summary["resources"] == 2  # bucket1 and bucket2
        assert summary["failures"] == 2
        assert summary["critical"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
