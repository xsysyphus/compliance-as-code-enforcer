# Test Infrastructure for Policy Validation

This directory contains intentionally non-compliant AWS infrastructure to demonstrate policy enforcement.

## Purpose

Validates that OPA policies correctly detect compliance violations before deployment.

## Intentional Violations

### CRITICAL Severity (3 violations)

1. **S3 Bucket - Missing Encryption** (SOC2-CC6.1/CC6.7)
   - Resource: `aws_s3_bucket.non_compliant_bucket`
   - Violation: No server-side encryption configured
   - Policy: `policies/soc2/s3_encryption.rego`

2. **RDS Instance - Plaintext Password** (SOC2-CC6.1)
   - Resource: `aws_db_instance.non_compliant_database`
   - Violation: Password hardcoded in Terraform (not using Secrets Manager)
   - Policy: `policies/soc2/no_plaintext_secrets.rego`

3. **Security Group - Public SSH Access** (SOC2-CC6.6)
   - Resource: `aws_security_group.non_compliant_sg`
   - Violation: Port 22 open to 0.0.0.0/0
   - Policy: `policies/soc2/security_group_public_access.rego`

### HIGH Severity (2 violations)

4. **RDS Instance - Insufficient Backup Retention** (SOC2-A1.2)
   - Resource: `aws_db_instance.non_compliant_database`
   - Violation: Backup retention is 3 days (required: >= 7 days)
   - Policy: `policies/soc2/rds_backup_retention.rego`

5. **Security Group - Public Database Access** (SOC2-CC6.6)
   - Resource: `aws_security_group.non_compliant_sg`
   - Violation: Port 5432 (PostgreSQL) open to 0.0.0.0/0
   - Policy: `policies/soc2/security_group_public_access.rego`

## Testing Locally

### Prerequisites

```bash
# Install Conftest (if not already installed)
brew install conftest

# Install OPA
brew install opa
```

### Run Policy Validation

```bash
# Navigate to this directory
cd terraform/test-infrastructure/

# Test all policies against this infrastructure
conftest test *.tf --policy ../../policies/soc2/

# Expected output:
# FAIL - main.tf - SOC2-CC6.1/CC6.7: S3 bucket 'non_compliant_bucket' must have encryption
# FAIL - main.tf - SOC2-CC6.1: RDS instance 'non_compliant_database' has password in code
# FAIL - main.tf - SOC2-A1.2: RDS instance has backup retention of 3 days (required: >= 7)
# FAIL - main.tf - SOC2-CC6.6: Security group 'non_compliant_sg' allows public SSH access
# FAIL - main.tf - SOC2-CC6.6: Security group 'non_compliant_sg' allows public PostgreSQL access
#
# 5 tests, 5 failed
```

### Test Individual Policies

```bash
# Test only S3 encryption policy
conftest test main.tf --policy ../../policies/soc2/s3_encryption.rego

# Test only RDS backup policy
conftest test main.tf --policy ../../policies/soc2/rds_backup_retention.rego

# Test only security group policy
conftest test main.tf --policy ../../policies/soc2/security_group_public_access.rego
```

### Generate JSON Report

```bash
# Export violations as JSON for CI/CD integration
conftest test *.tf --policy ../../policies/soc2/ --output json > violations.json

# Pretty print the report
cat violations.json | jq '.'
```

## Deploying (Not Recommended)

**WARNING**: This infrastructure is intentionally insecure. Do NOT deploy to production AWS accounts.

If testing in a sandbox account:

```bash
terraform init
terraform plan
terraform apply

# Clean up immediately after testing
terraform destroy
```

## CI/CD Integration

This test infrastructure is used in GitHub Actions to verify policies work correctly:

```yaml
- name: Test Policies Against Violations
  run: |
    cd terraform/test-infrastructure
    conftest test *.tf --policy ../../policies/soc2/
    # Should fail with 5 violations - this confirms policies work!
```

## Compliant vs Non-Compliant Examples

### S3 Encryption

**❌ Non-Compliant:**
```hcl
resource "aws_s3_bucket" "non_compliant_bucket" {
  bucket = "my-bucket"
  # Missing encryption configuration
}
```

**✅ Compliant:**
```hcl
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### RDS Backup Retention

**❌ Non-Compliant:**
```hcl
resource "aws_db_instance" "bad" {
  backup_retention_period = 3  # Less than 7 days
}
```

**✅ Compliant:**
```hcl
resource "aws_db_instance" "good" {
  backup_retention_period = 7  # Meets minimum requirement
  backup_window          = "03:00-04:00"
}
```

### Security Group Access

**❌ Non-Compliant:**
```hcl
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Public SSH access
  }
}
```

**✅ Compliant:**
```hcl
resource "aws_security_group" "good" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restricted to internal network
  }
}
```

## Expected Test Results

When running `conftest test`:

- **Exit code**: Non-zero (failure) - this is expected!
- **Violations detected**: 5 (3 CRITICAL, 2 HIGH)
- **Policies passing**: CloudTrail configuration (compliant example)

## Troubleshooting

### No violations detected

If `conftest` reports 0 violations:
1. Verify policy path: `--policy ../../policies/soc2/`
2. Check OPA syntax: `opa check ../../policies/soc2/*.rego`
3. Run with verbose output: `conftest test --trace`

### Terraform errors

If `terraform plan` fails:
1. Ensure AWS credentials configured: `aws sts get-caller-identity`
2. Check region availability: Some RDS versions may not be available in all regions
3. Verify unique bucket names: S3 bucket names must be globally unique

## Next Steps

After validating policies locally:
1. Integrate into CI/CD pipeline (see `.github/workflows/`)
2. Deploy runtime monitoring (see `terraform/runtime-monitoring/`)
3. Configure auto-remediation for safe violations
