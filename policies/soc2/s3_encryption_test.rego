# Unit tests for S3 encryption policy
package soc2.s3_encryption

# Test: Deny bucket without encryption
test_deny_bucket_without_encryption {
    test_input := {
        "resource": {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-bucket"
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Warn when sensitive bucket uses SSE-S3 instead of KMS
test_warn_sensitive_bucket_prefers_kms {
    test_input := {
        "resource": {
            "aws_s3_bucket": {
                "sensitive_bucket": {
                    "bucket": "sensitive-data",
                    "tags": {
                        "DataClassification": "Sensitive"
                    }
                }
            },
            "aws_s3_bucket_server_side_encryption_configuration": {
                "sensitive_bucket": {
                    "bucket": "aws_s3_bucket.sensitive_bucket.id",
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": "AES256"
                        }]
                    }]
                }
            }
        }
    }

    results := warn with input as test_input
    count(results) > 0
}

# Test: Warn when using AWS-managed KMS key without explicit kms_master_key_id
test_warn_aws_managed_kms_key {
    test_input := {
        "resource": {
            "aws_s3_bucket": {
                "kms_bucket": {
                    "bucket": "kms-bucket"
                }
            },
            "aws_s3_bucket_server_side_encryption_configuration": {
                "kms_bucket": {
                    "bucket": "aws_s3_bucket.kms_bucket.id",
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": "aws:kms"
                        }]
                    }]
                }
            }
        }
    }

    results := warn with input as test_input
    count(results) > 0
}

# Test: Allow bucket with separate encryption configuration (Terraform 4.0+)
test_allow_bucket_with_separate_encryption {
    test_input := {
        "resource": {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-bucket"
                }
            },
            "aws_s3_bucket_server_side_encryption_configuration": {
                "test_bucket": {
                    "bucket": "aws_s3_bucket.test_bucket.id",
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": "AES256"
                        }]
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) == 0
}

# Test: Allow bucket with inline encryption (legacy)
test_allow_bucket_with_inline_encryption {
    test_input := {
        "resource": {
            "aws_s3_bucket": {
                "test_bucket": {
                    "bucket": "my-bucket",
                    "server_side_encryption_configuration": [{
                        "rule": [{
                            "apply_server_side_encryption_by_default": [{
                                "sse_algorithm": "aws:kms",
                                "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/12345"
                            }]
                        }]
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) == 0
}

# Test: Deny unsupported encryption algorithm
test_deny_unsupported_algorithm {
    test_input := {
        "resource": {
            "aws_s3_bucket_server_side_encryption_configuration": {
                "test_bucket": {
                    "bucket": "aws_s3_bucket.test_bucket.id",
                    "rule": [{
                        "apply_server_side_encryption_by_default": [{
                            "sse_algorithm": "DES"  # Invalid algorithm
                        }]
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}
