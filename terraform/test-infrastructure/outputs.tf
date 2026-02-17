# Outputs for test infrastructure

output "test_summary" {
  description = "Summary of compliance test results"
  value = {
    compliant_resources = {
      s3_bucket          = aws_s3_bucket.compliant_bucket.id
      rds_instance       = aws_db_instance.compliant_database.id
      security_group     = aws_security_group.compliant_sg.id
      cloudtrail         = aws_cloudtrail.compliant_trail.id
    }
    non_compliant_resources = {
      s3_bucket      = aws_s3_bucket.non_compliant_bucket.id
      rds_instance   = aws_db_instance.non_compliant_database.id
      security_group = aws_security_group.non_compliant_sg.id
    }
    expected_violations = {
      critical = 3  # Unencrypted S3, plaintext password, public SSH
      high     = 2  # Insufficient backup retention, public PostgreSQL
      total    = 5
    }
  }
}

output "policy_test_instructions" {
  description = "Instructions to test policies"
  value = <<-EOT
    To test compliance policies:

    1. Run OPA policies against this infrastructure:
       conftest test *.tf --policy ../../policies/soc2/

    2. Expected violations:
       - S3 bucket without encryption (CRITICAL)
       - RDS with plaintext password (CRITICAL)
       - RDS backup retention < 7 days (HIGH)
       - Security group with SSH open to 0.0.0.0/0 (HIGH)
       - Security group with PostgreSQL open to 0.0.0.0/0 (HIGH)

    3. To see compliant resources, check outputs above.
  EOT
}

output "non_compliant_bucket_name" {
  description = "Name of intentionally non-compliant S3 bucket"
  value       = aws_s3_bucket.non_compliant_bucket.id
}

output "compliant_bucket_name" {
  description = "Name of compliant S3 bucket"
  value       = aws_s3_bucket.compliant_bucket.id
}
