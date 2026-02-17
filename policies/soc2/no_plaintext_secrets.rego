# SOC2 Control: CC6.1 (Logical Access - Credentials Protection)
# LGPD: Art. 46 (Administrative and technical safeguards)
# ISO 27001: A.9.4.1 (Information access restriction)
#
# Requirement: Secrets MUST NOT be stored in plaintext in code or configuration
# Rationale: Hardcoded secrets in IaC are visible in version control, logs, and to anyone with code access
# Severity: CRITICAL
# Auto-Remediation: Not supported (requires manual secret migration)

package soc2.no_plaintext_secrets

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# Keywords indicating secrets in attribute names
secret_keywords := [
    "password",
    "secret",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "token",
    "credential",
    "auth",
    "passwd",
    "key",
]

# CRITICAL: RDS database passwords in plaintext
deny[msg] {
    db := input.resource.aws_db_instance[name]
    db.password
    not is_secrets_manager_reference(db.password)
    not is_variable_reference(db.password)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.1]: RDS instance '%s' has plaintext password", [name]),
        "details": "Database password is hardcoded in Terraform. Anyone with access to this code can see the password. This violates security best practices and compliance requirements.",
        "remediation": concat("\n", [
            "Option 1 - RDS-managed password (recommended for RDS >= 6.0):",
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            "    manage_master_user_password = true",
            "    # Password stored automatically in Secrets Manager",
            "  }",
            "",
            "Option 2 - Explicit Secrets Manager reference:",
            "  data \"aws_secretsmanager_secret_version\" \"db_password\" {",
            sprintf("    secret_id = \"rds/%s/password\"", [name]),
            "  }",
            "",
            sprintf("  resource \"aws_db_instance\" \"%s\" {", [name]),
            "    password = jsondecode(data.aws_secretsmanager_secret_version.db_password.secret_string)[\"password\"]",
            "  }",
            "",
            "Option 3 - Terraform variable (password stored in CI/CD secrets):",
            "  variable \"db_password\" {",
            "    sensitive = true",
            "  }",
            sprintf("  password = var.db_password  # In resource '%s'", [name]),
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.1", "LGPD-Art.46", "ISO27001-A.9.4.1"],
    }
}

# CRITICAL: Hardcoded secrets in any resource attribute
deny[msg] {
    resource_type := input.resource[rt]
    resource := resource_type[name]

    # Find attributes that look like secrets
    attr_name := [key | resource[key]; contains_secret_keyword(key)][_]
    attr_value := resource[attr_name]

    # Check if it's a hardcoded string (not a reference)
    is_hardcoded_string(attr_value)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.1]: Resource '%s.%s' has hardcoded secret in '%s'", [rt, name, attr_name]),
        "details": sprintf("The attribute '%s' appears to contain a secret but is hardcoded as a string. Secrets must be stored securely and referenced.", [attr_name]),
        "remediation": concat("\n", [
            "Store the secret in AWS Secrets Manager:",
            sprintf("  aws secretsmanager create-secret --name \"%s/%s\" --secret-string '{\"value\":\"YOUR_SECRET\"}'", [rt, name]),
            "",
            "Reference it in Terraform:",
            sprintf("  data \"aws_secretsmanager_secret_version\" \"%s_%s\" {", [name, attr_name]),
            sprintf("    secret_id = \"%s/%s\"", [rt, name]),
            "  }",
            "",
            sprintf("  %s = jsondecode(data.aws_secretsmanager_secret_version.%s_%s.secret_string)[\"value\"]", [attr_name, name, attr_name]),
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.1"],
    }
}

# CRITICAL: Lambda environment variables with secrets
deny[msg] {
    lambda := input.resource.aws_lambda_function[name]
    env := lambda.environment[_]
    env_vars := env.variables

    # Find environment variables that look like secrets
    secret_var := [key | env_vars[key]; contains_secret_keyword(key)][_]
    secret_value := env_vars[secret_var]

    # Check if it's hardcoded
    is_hardcoded_string(secret_value)

    msg := {
        "msg": sprintf("CRITICAL [SOC2-CC6.1]: Lambda '%s' has plaintext secret in env var '%s'", [name, secret_var]),
        "details": "Lambda environment variables are visible in console and CloudTrail logs. Secrets should be stored in Secrets Manager or Parameter Store and fetched at runtime.",
        "remediation": concat("\n", [
            "Option 1 - Fetch secret at runtime (recommended):",
            "  # Remove from environment variables",
            "  # In Lambda code, fetch from Secrets Manager:",
            "  import boto3",
            "  secrets = boto3.client('secretsmanager')",
            sprintf("  secret = secrets.get_secret_value(SecretId='lambda/%s/%s')", [name, secret_var]),
            "",
            "Option 2 - Reference via Terraform (visible in logs):",
            sprintf("  data \"aws_secretsmanager_secret_version\" \"%s\" {", [secret_var]),
            sprintf("    secret_id = \"lambda/%s/%s\"", [name, secret_var]),
            "  }",
            "  environment {",
            "    variables = {",
            sprintf("      %s = data.aws_secretsmanager_secret_version.%s.secret_string", [secret_var, secret_var]),
            "    }",
            "  }",
        ]),
        "severity": "CRITICAL",
        "compliance": ["SOC2-CC6.1"],
    }
}

# HIGH: API Gateway API keys in plaintext
deny[msg] {
    api_key := input.resource.aws_api_gateway_api_key[name]
    api_key.value
    is_hardcoded_string(api_key.value)

    msg := {
        "msg": sprintf("HIGH [SOC2-CC6.1]: API Gateway key '%s' has hardcoded value", [name]),
        "details": "API keys should be generated by AWS, not hardcoded in Terraform.",
        "remediation": sprintf("Remove 'value' attribute from aws_api_gateway_api_key.%s - AWS will generate a secure random key", [name]),
        "severity": "HIGH",
    }
}

# MEDIUM: IAM user access keys (should use roles instead)
warn[msg] {
    user := input.resource.aws_iam_user[name]

    msg := {
        "msg": sprintf("MEDIUM [SOC2-CC6.1]: IAM user '%s' created (consider using roles instead)", [name]),
        "details": "IAM users with programmatic access require long-term credentials. IAM roles with temporary credentials are more secure.",
        "remediation": "Consider using IAM roles with OIDC/SAML federation or assuming roles instead of IAM users.",
        "severity": "MEDIUM",
    }
}

# Helper: Check if value contains secret keyword
contains_secret_keyword(attr_name) if {
    lower_attr := lower(attr_name)
    keyword := secret_keywords[_]
    contains(lower_attr, keyword)
}

# Helper: Check if string is hardcoded (not a reference)
is_hardcoded_string(value) if {
    is_string(value)
    not is_secrets_manager_reference(value)
    not is_variable_reference(value)
    not is_resource_reference(value)
    not is_data_reference(value)
    not value == ""  # Empty strings are ok (disabled feature)
}

# Helper: Check if value references Secrets Manager
is_secrets_manager_reference(value) if {
    is_string(value)
    contains(value, "aws_secretsmanager_secret")
}

is_secrets_manager_reference(value) if {
    is_string(value)
    contains(value, "secretsmanager")
}

# Helper: Check if value is a Terraform variable
is_variable_reference(value) if {
    is_string(value)
    startswith(value, "var.")
}

# Helper: Check if value references a resource
is_resource_reference(value) if {
    is_string(value)
    contains(value, "aws_")
    contains(value, ".")
}

# Helper: Check if value references data source
is_data_reference(value) if {
    is_string(value)
    startswith(value, "data.")
}
