# =============================================================================
# 보안 알림 파이프라인 (ADR-005 결정 4)
# =============================================================================
# GuardDuty/Security Hub의 High/Critical 파인딩을 EventBridge로 잡아서 SNS로
# 보내고, SNS 구독자로 AWS Chatbot(Slack 공식 연동, Lambda 불필요)과 PagerDuty
# (SNS를 직접 구독하는 공식 연동 지원)를 붙인다. ADR-014의 자동조치 결과 알림도
# 같은 SNS 토픽을 재사용한다.

variable "slack_workspace_id" {
  description = "AWS Chatbot에 연결할 Slack 워크스페이스 ID (Slack 앱에서 AWS Chatbot 설치 후 확인 가능)"
  type        = string
  default     = ""
}

variable "slack_channel_id" {
  description = "알림을 받을 Slack 채널 ID (#sec-alerts)"
  type        = string
  default     = ""
}

variable "pagerduty_integration_url" {
  description = "PagerDuty의 AWS CloudWatch/SNS 연동 엔드포인트 URL (PagerDuty 서비스 설정에서 발급)"
  type        = string
  default     = ""
  sensitive   = true
}

resource "aws_sns_topic" "security_alerts" {
  name = "${local.name_prefix}-security-alerts"
}

# ---------- EventBridge: GuardDuty/Security Hub High·Critical만 필터링 ----------
resource "aws_cloudwatch_event_rule" "security_findings_critical" {
  name        = "${local.name_prefix}-security-findings-critical"
  description = "GuardDuty/Security Hub의 High/Critical 파인딩만 잡음 (ADR-005 결정 4)"

  event_pattern = jsonencode({
    source      = ["aws.guardduty", "aws.securityhub"]
    detail-type = ["GuardDuty Finding", "Security Hub Findings - Imported"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule = aws_cloudwatch_event_rule.security_findings_critical.name
  arn  = aws_sns_topic.security_alerts.arn

  # 원본 ASFF/GuardDuty JSON은 장황해서, Slack/PagerDuty에 필요한 필드만 축약
  # (ADR-003 결정 4의 Input Transformer 방침 그대로 재사용)
  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      title    = "$.detail.title"
      resource = "$.detail.resources[0].id"
      account  = "$.account"
      region   = "$.region"
    }
    input_template = "\"[<severity>] <title> - resource=<resource>, account=<account>, region=<region>\""
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridge"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.security_alerts.arn
    }]
  })
}

# ---------- Slack (AWS Chatbot, Lambda 없이 공식 연동) ----------
resource "aws_iam_role" "chatbot" {
  name = "${local.name_prefix}-chatbot-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "chatbot.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "chatbot_readonly" {
  role       = aws_iam_role.chatbot.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess" # Chatbot이 조회용으로 필요한 최소 수준
}

resource "aws_chatbot_slack_channel_configuration" "sec_alerts" {
  count = var.slack_workspace_id != "" ? 1 : 0

  configuration_name = "${local.name_prefix}-sec-alerts"
  iam_role_arn        = aws_iam_role.chatbot.arn
  slack_channel_id    = var.slack_channel_id
  slack_team_id       = var.slack_workspace_id
  sns_topic_arns      = [aws_sns_topic.security_alerts.arn]
}

# ---------- PagerDuty (SNS HTTPS 구독, PagerDuty 공식 연동) ----------
resource "aws_sns_topic_subscription" "pagerduty" {
  count     = var.pagerduty_integration_url != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "https"
  endpoint  = var.pagerduty_integration_url
}

output "security_alerts_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}
