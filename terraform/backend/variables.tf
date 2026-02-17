# Backend configuration variables
variable "aws_region" {
  description = "AWS region where the backend resources will be created."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for tagging and naming."
  type        = string
  default     = "compliance-as-code"
}

variable "environment" {
  description = "Environment name for the backend (e.g., shared, prod, dev)."
  type        = string
  default     = "shared"
}

variable "force_destroy" {
  description = "Allow bucket deletion even if it contains objects (use with caution)."
  type        = bool
  default     = false
}
