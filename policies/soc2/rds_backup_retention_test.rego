# Unit tests for RDS backup retention policy
package soc2.rds_backup_retention

# Test: Deny RDS with insufficient backup retention
test_deny_insufficient_retention {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "test_db": {
                    "identifier": "test-db",
                    "backup_retention_period": 3  # Less than 7 days
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Allow RDS with sufficient backup retention
test_allow_sufficient_retention {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "test_db": {
                    "identifier": "test-db",
                    "storage_encrypted": true,
                    "publicly_accessible": false,
                    "backup_retention_period": 7
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) == 0
}

# Test: Deny RDS without backup retention specified
test_deny_no_backup_retention {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "test_db": {
                    "identifier": "test-db"
                    # No backup_retention_period specified
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Allow RDS with extended retention
test_allow_extended_retention {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "test_db": {
                    "identifier": "test-db",
                    "storage_encrypted": true,
                    "publicly_accessible": false,
                    "backup_retention_period": 30
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) == 0
}

# Test: Deny when encryption at rest is disabled
test_deny_missing_encryption {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "test_db": {
                    "identifier": "test-db",
                    "publicly_accessible": false,
                    "backup_retention_period": 7,
                    "storage_encrypted": false
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Deny when instance is publicly accessible
test_deny_public_rds_instance {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "test_db": {
                    "identifier": "test-db",
                    "publicly_accessible": true,
                    "backup_retention_period": 7,
                    "storage_encrypted": true
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}
