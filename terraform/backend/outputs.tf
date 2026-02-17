output "state_bucket" {
  description = "Name of the S3 bucket storing Terraform state."
  value       = aws_s3_bucket.tfstate.bucket
}

output "dynamodb_lock_table" {
  description = "Name of the DynamoDB table used for state locking."
  value       = aws_dynamodb_table.tf_locks.name
}

output "region" {
  description = "Region where backend was provisioned."
  value       = var.aws_region
}
