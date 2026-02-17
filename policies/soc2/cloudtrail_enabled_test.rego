# Unit tests for CloudTrail compliance policy
package soc2.cloudtrail_enabled

# Test: Deny when no CloudTrail trails exist
test_deny_no_trail_configured {
    test_input := {
        "resource": {
            "aws_cloudtrail": {}
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Deny when trail is not multi-region
test_deny_single_region_trail {
    test_input := {
        "resource": {
            "aws_cloudtrail": {
                "main": {
                    "name": "org-trail",
                    "is_multi_region_trail": false,
                    "enable_log_file_validation": true,
                    "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
                    "include_global_service_events": true
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Deny when KMS encryption is missing
test_deny_missing_kms_encryption {
    test_input := {
        "resource": {
            "aws_cloudtrail": {
                "main": {
                    "name": "org-trail",
                    "is_multi_region_trail": true,
                    "enable_log_file_validation": true,
                    "include_global_service_events": true
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Warn when lifecycle policy is missing on the CloudTrail bucket
test_warn_missing_lifecycle_policy {
    test_input := {
        "resource": {
            "aws_cloudtrail": {
                "main": {
                    "name": "org-trail",
                    "is_multi_region_trail": true,
                    "enable_log_file_validation": true,
                    "kms_key_id": "arn:aws:kms:us-east-1:111122223333:key/abc",
                    "include_global_service_events": true,
                    "s3_bucket_name": "aws_s3_bucket.cloudtrail_logs.id"
                }
            },
            "aws_s3_bucket": {
                "cloudtrail_logs": {
                    "bucket": "cloudtrail-logs"
                }
            }
        }
    }

    results := warn with input as test_input
    count(results) > 0
}
