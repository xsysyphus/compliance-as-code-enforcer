# SOC2 Controls: CC7.2 (Monitoring), CC7.3 (Audit Logging), CC7.4 (Forensic Analysis)
# LGPD: Art. 37, 48 (Audit logs for data processing accountability)
# ISO 27001: A.12.4.1 (Event logging), A.12.4.3 (Administrator logs)
#
# Requirement: CloudTrail MUST be enabled with proper configuration for audit trails
# Rationale: Provides forensic evidence, supports incident response, enables compliance audits
# Severity: CRITICAL
# Auto-Remediation: Supported

package soc2.cloudtrail_enabled

import future.keywords.if
import future.keywords.contains

# CRITICAL: No CloudTrail trail configured at all
deny[msg] {
    count(input.resource.aws_cloudtrail) == 0

    msg := {
        "msg": "CRITICAL [SOC2-CC7.2/CC7.3]: No CloudTrail trail configured in this infrastructure",
        "details": "CloudTrail is required for audit logging, incident response, and compliance. Without it, you have no record of API activity in your AWS account.",
        "remediation": concat("\n", [
            "Create a multi-region CloudTrail trail:",
            "  resource \"aws_kms_key\" \"cloudtrail\" {",
            "    description         = \"CloudTrail log encryption\"",
            "    enable_key_rotation = true",
            "  }",
            "",
            "  resource \"aws_s3_bucket\" \"cloudtrail\" {",
            "    bucket = \"my-org-cloudtrail-logs\"",
            "  }",
            "",
            "  resource \"aws_cloudtrail\" \"main\" {",
            "    name                          = \"organization-trail\"",
            "    s3_bucket_name                = aws_s3_bucket.cloudtrail.id",
            "    include_global_service_events = true",
            "    is_multi_region_trail         = true",
            "    enable_log_file_validation    = true",
            "    kms_key_id                    = aws_kms_key.cloudtrail.arn",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC7.2", "SOC2-CC7.3", "LGPD-Art.37", "ISO27001-A.12.4.1"],
    }
}

# CRITICAL: CloudTrail not configured for multi-region
deny[msg] {
    trail := input.resource.aws_cloudtrail[name]
    not trail.is_multi_region_trail

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC7.2]: CloudTrail '%s' is not multi-region", [name]),
        "details": "Single-region trails do not capture events from other AWS regions. Multi-region trails are required for complete visibility.",
        "remediation": sprintf("Set is_multi_region_trail = true for trail '%s'", [name]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC7.2"],
    }
}

# CRITICAL: CloudTrail without log file validation (integrity)
deny[msg] {
    trail := input.resource.aws_cloudtrail[name]
    not trail.enable_log_file_validation

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC7.3]: CloudTrail '%s' lacks log file validation", [name]),
        "details": "Log file validation uses digital signatures to verify log integrity. Without it, you cannot prove logs haven't been tampered with.",
        "remediation": sprintf("Set enable_log_file_validation = true for trail '%s'", [name]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC7.3", "SOC2-CC7.4"],
    }
}

# CRITICAL: CloudTrail without encryption
deny[msg] {
    trail := input.resource.aws_cloudtrail[name]
    not trail.kms_key_id

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.7]: CloudTrail '%s' does not encrypt logs", [name]),
        "details": "CloudTrail logs contain sensitive information about API activity. Logs must be encrypted with KMS.",
        "remediation": concat("\n", [
            sprintf("Add KMS encryption to trail '%s':", [name]),
            "  resource \"aws_kms_key\" \"cloudtrail\" {",
            "    description         = \"CloudTrail log encryption\"",
            "    enable_key_rotation = true",
            "    policy = jsonencode({",
            "      Statement = [{",
            "        Sid    = \"Enable CloudTrail Encrypt\"",
            "        Effect = \"Allow\"",
            "        Principal = { Service = \"cloudtrail.amazonaws.com\" }",
            "        Action = [\"kms:GenerateDataKey*\", \"kms:DecryptDataKey\"]",
            "      }]",
            "    })",
            "  }",
            "",
            sprintf("  kms_key_id = aws_kms_key.cloudtrail.arn  # Add to trail '%s'", [name]),
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.7", "LGPD-Art.46"],
    }
}

# HIGH: CloudTrail not capturing global service events
deny[msg] {
    trail := input.resource.aws_cloudtrail[name]
    trail.include_global_service_events == false

    msg := {
        "msg": sprintf("HIGH [SOC2-CC7.2]: CloudTrail '%s' excludes global service events", [name]),
        "details": "Global services (IAM, STS, CloudFront) generate events in us-east-1. Excluding these means missing critical identity and access events.",
        "remediation": sprintf("Set include_global_service_events = true for trail '%s'", [name]),
        "severity": "HIGH",
        "compliance": ["SOC2-CC7.2"],
    }
}

# MEDIUM: CloudTrail S3 bucket without lifecycle policy
warn[msg] {
    trail := input.resource.aws_cloudtrail[name]
    bucket_name := extract_bucket_name(trail.s3_bucket_name)
    input.resource.aws_s3_bucket[bucket_name]
    not input.resource.aws_s3_bucket_lifecycle_configuration[bucket_name]

    msg := {
        "msg": sprintf("MEDIUM [SOC2-A1.2]: CloudTrail bucket '%s' lacks lifecycle policy", [bucket_name]),
        "details": "CloudTrail logs can become expensive over time. Lifecycle policies transition old logs to cheaper storage.",
        "remediation": concat("\n", [
            sprintf("Add lifecycle policy to bucket '%s':", [bucket_name]),
            "  resource \"aws_s3_bucket_lifecycle_configuration\" \"cloudtrail\" {",
            sprintf("    bucket = aws_s3_bucket.%s.id", [bucket_name]),
            "    rule {",
            "      id     = \"archive-old-logs\"",
            "      status = \"Enabled\"",
            "      transition {",
            "        days          = 90",
            "        storage_class = \"GLACIER\"",
            "      }",
            "      expiration {",
            "        days = 2555  # 7 years (compliance requirement)",
            "      }",
            "    }",
            "  }",
        ]),
        "severity": "MEDIUM",
    }
}

# MEDIUM: CloudTrail should send logs to CloudWatch
warn[msg] {
    trail := input.resource.aws_cloudtrail[name]
    not trail.cloud_watch_logs_group_arn

    msg := {
        "msg": sprintf("MEDIUM [SOC2-CC7.2]: CloudTrail '%s' not integrated with CloudWatch Logs", [name]),
        "details": "CloudWatch Logs enable real-time monitoring and alerting on CloudTrail events (e.g., root account usage, unauthorized API calls).",
        "remediation": concat("\n", [
            sprintf("Add CloudWatch Logs integration to trail '%s':", [name]),
            "  resource \"aws_cloudwatch_log_group\" \"cloudtrail\" {",
            "    name              = \"/aws/cloudtrail/organization-trail\"",
            "    retention_in_days = 90",
            "  }",
            "",
            "  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn",
            "  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn",
        ]),
        "severity": "MEDIUM",
    }
}

# MEDIUM: CloudTrail should have SNS notification
warn[msg] {
    trail := input.resource.aws_cloudtrail[name]
    not trail.sns_topic_name

    msg := {
        "msg": sprintf("MEDIUM [SOC2-CC7.2]: CloudTrail '%s' has no SNS notifications", [name]),
        "details": "SNS notifications can alert security teams when new CloudTrail logs are delivered, enabling faster incident response.",
        "remediation": sprintf("Configure sns_topic_name for trail '%s' to enable notifications", [name]),
        "severity": "MEDIUM",
    }
}

# LOW: CloudTrail event selectors for data events
warn[msg] {
    trail := input.resource.aws_cloudtrail[name]
    not trail.event_selector

    msg := {
        "msg": sprintf("LOW [Best Practice]: CloudTrail '%s' has no event selectors configured", [name]),
        "details": "Event selectors allow logging S3 object-level and Lambda invocation events for enhanced visibility.",
        "remediation": concat("\n", [
            "Add event selectors for data events:",
            "  event_selector {",
            "    read_write_type           = \"All\"",
            "    include_management_events = true",
            "    data_resource {",
            "      type   = \"AWS::S3::Object\"",
            "      values = [\"arn:aws:s3:::sensitive-bucket/*\"]",
            "    }",
            "  }",
        ]),
        "severity": "LOW",
    }
}

# Helper: Extract bucket name from Terraform reference
extract_bucket_name(s3_ref) := name if {
    contains(s3_ref, "aws_s3_bucket.")
    parts := split(s3_ref, ".")
    name := parts[1]
}

extract_bucket_name(s3_ref) := s3_ref if {
    not contains(s3_ref, "aws_s3_bucket.")
}
