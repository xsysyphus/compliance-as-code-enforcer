# Unit tests for plaintext secrets policy
package soc2.no_plaintext_secrets

# Test: Deny hardcoded RDS password
test_deny_rds_plaintext_password {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "db": {
                    "identifier": "app-db",
                    "password": "Plaintext123!"
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Allow RDS when password is managed (no plaintext)
test_allow_rds_with_managed_password {
    test_input := {
        "resource": {
            "aws_db_instance": {
                "db": {
                    "identifier": "app-db",
                    "manage_master_user_password": true
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) == 0
}

# Test: Deny Lambda environment variable with hardcoded secret
test_deny_lambda_env_plaintext_secret {
    test_input := {
        "resource": {
            "aws_lambda_function": {
                "handler": {
                    "function_name": "lambda-handler",
                    "environment": [{
                        "variables": {
                            "API_KEY": "hardcoded-key"
                        }
                    }]
                }
            }
        }
    }

    results := deny with input as test_input
    count(results) > 0
}

# Test: Warn when IAM user is created
test_warn_iam_user_creation {
    test_input := {
        "resource": {
            "aws_iam_user": {
                "developer": {
                    "name": "developer-user"
                }
            }
        }
    }

    results := warn with input as test_input
    count(results) > 0
}
