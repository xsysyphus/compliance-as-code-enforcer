output "lambda_function_name" {
  description = "Name of the compliance scanner Lambda."
  value       = aws_lambda_function.scanner.function_name
}

output "dynamodb_table" {
  description = "DynamoDB table storing scan findings."
  value       = aws_dynamodb_table.findings.name
}

output "evidence_bucket" {
  description = "S3 bucket used to store evidence JSON."
  value       = aws_s3_bucket.evidence.bucket
}

output "event_rule_arn" {
  description = "EventBridge rule ARN triggering daily scans."
  value       = aws_cloudwatch_event_rule.daily.arn
}
