variable "aws_region" {
  description = "AWS region for runtime monitoring stack."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for tagging and naming."
  type        = string
  default     = "compliance-as-code"
}

variable "environment" {
  description = "Environment name (e.g., prod, staging, shared)."
  type        = string
  default     = "prod"
}

variable "force_destroy" {
  description = "Allow destroying buckets with content (use only in test/sandbox)."
  type        = bool
  default     = false
}

variable "evidence_retention_days" {
  description = "How long to retain evidence objects in S3."
  type        = number
  default     = 2555 # ~7 years
}

variable "log_retention_days" {
  description = "Retention for Lambda CloudWatch logs."
  type        = number
  default     = 90
}

variable "scan_schedule" {
  description = "EventBridge schedule expression for scans."
  type        = string
  default     = "cron(0 2 * * ? *)" # Daily at 02:00 UTC
}

variable "lambda_memory" {
  description = "Lambda memory size (MB)."
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 300
}

variable "log_level" {
  description = "Log level for scanner."
  type        = string
  default     = "INFO"
}

variable "min_rds_backup_days" {
  description = "Minimum RDS backup retention enforced at runtime."
  type        = number
  default     = 7
}

variable "alarm_topic_arn" {
  description = "SNS topic ARN for alarm notifications (leave empty to disable actions)."
  type        = string
  default     = ""
}

variable "minimum_compliance_score" {
  description = "Minimum acceptable compliance score (%) before raising alarm."
  type        = number
  default     = 90
}
