terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "runtime-monitoring"
    }
  }
}

locals {
  suffix          = random_id.evidence_suffix.hex
  evidence_bucket = lower("${var.project_name}-${var.environment}-evidence-${local.suffix}")
  table_name      = lower("${var.project_name}-${var.environment}-compliance-runs")
  function_name   = "${var.project_name}-${var.environment}-scanner"
  log_group       = "/aws/lambda/${local.function_name}"
}

resource "random_id" "evidence_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "evidence" {
  bucket        = local.evidence_bucket
  force_destroy = var.force_destroy
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "expire-evidence"
    status = "Enabled"

    expiration {
      days = var.evidence_retention_days
    }
  }
}

resource "aws_dynamodb_table" "findings" {
  name           = local.table_name
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "pk"
  range_key      = "sk"
  stream_enabled = false

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

data "archive_file" "scanner_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../lambda/scanner"
  output_path = "${path.module}/scanner.zip"
}

resource "aws_iam_role" "scanner" {
  name = "${local.function_name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "scanner" {
  name = "${local.function_name}-policy"
  role = aws_iam_role.scanner.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketEncryption",
          "s3:GetBucketLocation"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "s3:PutObject"
        ],
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "rds:DescribeDBInstances",
          "ec2:DescribeSecurityGroups",
          "cloudtrail:DescribeTrails"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "dynamodb:BatchWriteItem",
          "dynamodb:PutItem"
        ],
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "scanner" {
  function_name = local.function_name
  role          = aws_iam_role.scanner.arn
  handler       = "main.lambda_handler"
  runtime       = "python3.11"
  timeout       = var.lambda_timeout
  memory_size   = var.lambda_memory

  filename         = data.archive_file.scanner_zip.output_path
  source_code_hash = data.archive_file.scanner_zip.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL           = var.log_level
      DYNAMO_TABLE        = aws_dynamodb_table.findings.name
      EVIDENCE_BUCKET     = aws_s3_bucket.evidence.bucket
      MIN_RDS_BACKUP_DAYS = tostring(var.min_rds_backup_days)
      SCAN_REGION         = var.aws_region
    }
  }
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_event_rule" "daily" {
  name                = "${local.function_name}-schedule"
  description         = "Daily compliance scan"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "daily" {
  rule      = aws_cloudwatch_event_rule.daily.name
  target_id = "lambda"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "allow_events" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily.arn
}
