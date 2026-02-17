locals {
  alarm_actions = var.alarm_topic_arn != "" ? [var.alarm_topic_arn] : []
}

# Transform structured summary logs into metrics
resource "aws_cloudwatch_log_metric_filter" "summary" {
  name           = "${local.function_name}-summary-metrics"
  log_group_name = aws_cloudwatch_log_group.scanner.name
  pattern        = "{ $.event = \"compliance_scan_summary\" }"

  metric_transformation {
    name      = "Resources"
    namespace = "Compliance/Runtime"
    value     = "$.resources"
  }

  metric_transformation {
    name      = "Failures"
    namespace = "Compliance/Runtime"
    value     = "$.failures"
  }

  metric_transformation {
    name      = "Critical"
    namespace = "Compliance/Runtime"
    value     = "$.critical"
  }
}

resource "aws_cloudwatch_metric_alarm" "critical_violations" {
  alarm_name          = "${local.function_name}-critical-violations"
  alarm_description   = "Triggers when runtime scan reports CRITICAL violations."
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  threshold           = 1
  datapoints_to_alarm = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions

  metric_name = "Critical"
  namespace   = "Compliance/Runtime"
  period      = 300
  statistic   = "Maximum"
}

resource "aws_cloudwatch_metric_alarm" "compliance_score" {
  alarm_name          = "${local.function_name}-score-low"
  alarm_description   = "Compliance score fell below threshold based on runtime scan."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  threshold           = var.minimum_compliance_score
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions

  metric_query {
    id = "resources"
    metric {
      metric_name = "Resources"
      namespace   = "Compliance/Runtime"
      period      = 300
      stat        = "Average"
    }
  }

  metric_query {
    id = "failures"
    metric {
      metric_name = "Failures"
      namespace   = "Compliance/Runtime"
      period      = 300
      stat        = "Average"
    }
  }

  metric_query {
    id          = "score"
    expression  = "100*(resources - failures)/resources"
    label       = "ComplianceScore"
    return_data = true
  }
}
