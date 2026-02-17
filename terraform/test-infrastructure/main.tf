# Compliance-as-Code Enforcer - Test Infrastructure
# This intentionally creates non-compliant resources to demonstrate policy enforcement
# SEVERITY VIOLATIONS: 3 CRITICAL, 2 HIGH

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "compliance-as-code-test"
      ManagedBy   = "terraform"
      Environment = "test"
    }
  }
}

#
# S3 BUCKETS - Testing Encryption Policy
#

# ❌ VIOLATION: SOC2-CC6.1/CC6.7 - Missing encryption
resource "aws_s3_bucket" "non_compliant_bucket" {
  bucket = "compliance-test-unencrypted-${data.aws_caller_identity.current.account_id}"

  # Intentionally missing: server_side_encryption_configuration
  # This WILL trigger policy violation
}

# ✅ COMPLIANT: S3 bucket with proper encryption
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "compliance-test-encrypted-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

#
# RDS INSTANCES - Testing Backup Retention Policy
#

# ❌ VIOLATION: SOC2-A1.2 - Insufficient backup retention (3 days < 7 days required)
resource "aws_db_instance" "non_compliant_database" {
  identifier           = "compliance-test-db-noncompliant"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "TemporaryPassword123!"  # ❌ VIOLATION: Plaintext password (SOC2-CC6.1)
  skip_final_snapshot  = true
  publicly_accessible  = false

  backup_retention_period = 3  # ❌ CRITICAL: Less than 7 days required

  tags = {
    Name        = "non-compliant-test-db"
    Compliance  = "intentional-violation"
  }
}

# ✅ COMPLIANT: RDS with proper backup retention and managed password
resource "aws_db_instance" "compliant_database" {
  identifier           = "compliance-test-db-compliant"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  skip_final_snapshot  = true
  publicly_accessible  = false

  # ✅ Proper backup configuration
  backup_retention_period      = 7
  backup_window                = "03:00-04:00"
  manage_master_user_password  = true  # ✅ RDS-managed password in Secrets Manager

  tags = {
    Name = "compliant-test-db"
  }
}

#
# SECURITY GROUPS - Testing Public Access Policy
#

# ❌ VIOLATION: SOC2-CC6.6 - SSH (22) open to internet
resource "aws_security_group" "non_compliant_sg" {
  name        = "compliance-test-sg-noncompliant"
  description = "Intentionally insecure security group for testing"
  vpc_id      = aws_vpc.test_vpc.id

  # ❌ CRITICAL: SSH open to 0.0.0.0/0
  ingress {
    description = "SSH from anywhere (VIOLATION)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ❌ HIGH: PostgreSQL open to internet
  ingress {
    description = "PostgreSQL from anywhere (VIOLATION)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "non-compliant-sg"
  }
}

# ✅ COMPLIANT: Security group with restricted access
resource "aws_security_group" "compliant_sg" {
  name        = "compliance-test-sg-compliant"
  description = "Properly secured security group"
  vpc_id      = aws_vpc.test_vpc.id

  # ✅ SSH restricted to corporate VPN IP range
  ingress {
    description = "SSH from corporate network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal network only
  }

  # ✅ HTTPS from internet is acceptable
  ingress {
    description = "HTTPS from anywhere (acceptable)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "compliant-sg"
  }
}

#
# CLOUDTRAIL - Testing Audit Logging Policy
#

# ✅ COMPLIANT: CloudTrail with all required features
resource "aws_cloudtrail" "compliant_trail" {
  name                          = "compliance-test-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Name = "compliant-cloudtrail"
  }
}

# Supporting resources for CloudTrail
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "compliance-test-cloudtrail-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DecryptDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/compliance-test-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

#
# VPC - Supporting infrastructure
#

resource "aws_vpc" "test_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "compliance-test-vpc"
  }
}

data "aws_caller_identity" "current" {}
