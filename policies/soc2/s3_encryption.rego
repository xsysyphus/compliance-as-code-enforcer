# SOC2 Controls: CC6.1 (Logical Access), CC6.7 (Encryption)
# LGPD: Art. 46, 49 (Security measures for personal data)
# ISO 27001: A.10.1.1 (Cryptographic controls)
#
# Requirement: All S3 buckets MUST have encryption at rest enabled
# Rationale: Protects data confidentiality in case of unauthorized access to storage
# Severity: CRITICAL
# Auto-Remediation: Supported

package soc2.s3_encryption

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Acceptable encryption algorithms
acceptable_algorithms := ["AES256", "aws:kms"]

# CRITICAL: Deny S3 buckets without server-side encryption
deny[msg] {
    bucket := input.resource.aws_s3_bucket[bucket_name]
    not has_encryption(bucket_name)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.1/CC6.7]: S3 bucket '%s' lacks encryption at rest", [bucket_name]),
        "details": sprintf("Bucket '%s' does not have server-side encryption enabled. All S3 buckets must encrypt data at rest to protect confidentiality.", [bucket_name]),
        "remediation": concat("\n", [
            "Add encryption configuration using one of these methods:",
            "",
            "Method 1 - Separate resource (Terraform AWS Provider >= 4.0):",
            sprintf("  resource \"aws_s3_bucket_server_side_encryption_configuration\" \"%s\" {", [bucket_name]),
            sprintf("    bucket = aws_s3_bucket.%s.id", [bucket_name]),
            "    rule {",
            "      apply_server_side_encryption_by_default {",
            "        sse_algorithm = \"AES256\"  # Or \"aws:kms\" with kms_master_key_id",
            "      }",
            "    }",
            "  }",
            "",
            "Method 2 - KMS encryption (recommended for sensitive data):",
            "  resource \"aws_kms_key\" \"s3\" {",
            "    description = \"S3 bucket encryption key\"",
            "    enable_key_rotation = true",
            "  }",
            "",
            sprintf("  resource \"aws_s3_bucket_server_side_encryption_configuration\" \"%s\" {", [bucket_name]),
            sprintf("    bucket = aws_s3_bucket.%s.id", [bucket_name]),
            "    rule {",
            "      apply_server_side_encryption_by_default {",
            "        sse_algorithm     = \"aws:kms\"",
            "        kms_master_key_id = aws_kms_key.s3.arn",
            "      }",
            "    }",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.1", "SOC2-CC6.7", "LGPD-Art.46"],
    }
}

# Check if encryption is configured via separate resource (Terraform >= 4.0)
has_encryption(bucket_name) if {
    enc := input.resource.aws_s3_bucket_server_side_encryption_configuration[_]
    bucket_ref := sprintf("aws_s3_bucket.%s.id", [bucket_name])
    enc.bucket == bucket_ref
}

# Check for deprecated inline encryption (Terraform < 4.0, still supported)
has_encryption(bucket_name) if {
    bucket := input.resource.aws_s3_bucket[bucket_name]
    bucket.server_side_encryption_configuration[_]
}

# CRITICAL: Deny weak or unsupported encryption algorithms
deny[msg] {
    enc := input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    rule := enc.rule[_]
    default_enc := rule.apply_server_side_encryption_by_default[_]
    algorithm := default_enc.sse_algorithm

    not algorithm in acceptable_algorithms

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.7]: S3 encryption '%s' uses unsupported algorithm '%s'", [name, algorithm]),
        "details": sprintf("Encryption algorithm '%s' is not approved. Only AES256 (SSE-S3) and aws:kms (SSE-KMS) are permitted.", [algorithm]),
        "remediation": sprintf("Change sse_algorithm to one of: %v", [acceptable_algorithms]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.7"],
    }
}

# HIGH: Warn if using SSE-S3 instead of SSE-KMS for sensitive data buckets
warn[msg] {
    enc := input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    rule := enc.rule[_]
    default_enc := rule.apply_server_side_encryption_by_default[_]
    algorithm := default_enc.sse_algorithm

    algorithm == "AES256"

    # Check if bucket is tagged as sensitive
    bucket := input.resource.aws_s3_bucket[name]
    is_sensitive_bucket(bucket)

    msg := {
        "msg": sprintf("HIGH [SOC2-CC6.7]: Sensitive bucket '%s' uses SSE-S3 instead of SSE-KMS", [name]),
        "details": "Buckets tagged as 'Sensitive' or 'Production' should use KMS encryption for enhanced key management and audit capabilities.",
        "remediation": "Upgrade to SSE-KMS encryption with a customer-managed key for better control and compliance.",
        "severity": "HIGH",
        "compliance": ["SOC2-CC6.7", "LGPD-Art.49"],
    }
}

# HIGH: KMS encryption should use customer-managed keys, not AWS-managed
warn[msg] {
    enc := input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    rule := enc.rule[_]
    default_enc := rule.apply_server_side_encryption_by_default[_]

    default_enc.sse_algorithm == "aws:kms"
    not default_enc.kms_master_key_id  # Using AWS-managed key if not specified

    msg := {
        "msg": sprintf("MEDIUM [SOC2-CC6.7]: S3 bucket '%s' uses AWS-managed KMS key", [name]),
        "details": "While KMS encryption is enabled, using a customer-managed key provides better control and audit trails.",
        "remediation": "Specify kms_master_key_id with a customer-managed KMS key ARN.",
        "severity": "MEDIUM",
    }
}

# MEDIUM: Recommend bucket key for cost optimization with KMS
warn[msg] {
    enc := input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    rule := enc.rule[_]
    default_enc := rule.apply_server_side_encryption_by_default[_]

    default_enc.sse_algorithm == "aws:kms"
    not rule.bucket_key_enabled

    msg := {
        "msg": sprintf("LOW [Cost Optimization]: S3 bucket '%s' should enable bucket keys for KMS", [name]),
        "details": "Bucket keys reduce KMS request costs by up to 99% when using SSE-KMS.",
        "remediation": "Add 'bucket_key_enabled = true' to the encryption rule block.",
        "severity": "LOW",
    }
}

# Helper: Check if bucket is marked as sensitive
is_sensitive_bucket(bucket) if {
    bucket.tags.DataClassification == "Sensitive"
}

is_sensitive_bucket(bucket) if {
    bucket.tags.DataClassification == "Confidential"
}

is_sensitive_bucket(bucket) if {
    bucket.tags.Environment == "production"
}

is_sensitive_bucket(bucket) if {
    bucket.tags.Compliance == "PCI-DSS"
}

is_sensitive_bucket(bucket) if {
    bucket.tags.Compliance == "HIPAA"
}
