# Variables for test infrastructure

variable "aws_region" {
  description = "AWS region for test infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "compliance-as-code-test"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "test"
}
