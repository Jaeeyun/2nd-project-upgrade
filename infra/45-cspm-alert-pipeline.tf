# =============================================================================
# CSPM 실시간 알림 파이프라인 - Security Hub CRITICAL/HIGH 선별 + 컨텍스트 강화
# =============================================================================

# ---------- Slack 알림 발송 ----------
# 원래는 Incoming Webhook을 썼으나(인터랙티브 버튼이 필요없는 단방향
# 알림이라 더 단순하다고 판단), 이후 [위험 수용/예외 등록] 버튼을 추가하면서
# 제출 완료 시 원본 메시지를 chat.update로 갱신해야 하는 요구사항이 생겼다.
# Slack의 chat.update는 그 메시지를 올린 것과 "같은 봇(App)"만 수정할 수
# 있는데, Incoming Webhook은 28번 파일의 Bot Token과 별도 App/bot_id로
# 등록돼있어서 영원히 실패할 수밖에 없었다(라이브로 확인 - auth.test의
# bot_id와 Webhook 메시지의 bot_id가 서로 달랐음). 그래서 발송도 28번 파일의
# 같은 Bot Token(chat.postMessage)으로 통일한다 - 이 Secret은 더 안 쓰지만,
# 명시적으로 지워달라는 요청이 없어 일단 남겨둔다(필요 없으면
# terraform destroy -target=aws_secretsmanager_secret.cspm_slack_webhook로 정리 가능).
resource "aws_secretsmanager_secret" "cspm_slack_webhook" {
  name                    = "${local.name_prefix}-cspm-slack-webhook"
  description             = "[미사용] CSPM 알림을 Bot Token(chat.postMessage) 방식으로 바꾸면서 더 이상 안 씀"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "cspm_slack_webhook" {
  secret_id     = aws_secretsmanager_secret.cspm_slack_webhook.id
  secret_string = jsonencode({ webhook_url = "https://hooks.slack.com/services/여기에-실제-값을-채우세요" })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ---------- 24시간 중복 억제 ----------
resource "aws_dynamodb_table" "cspm_alert_dedup" {
  name         = "${local.name_prefix}-cspm-alert-dedup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# ---------- Lambda 실행 역할 ----------
data "archive_file" "cspm_alert_enrichment" {
  type        = "zip"
  source_file = "${path.module}/scripts/cspm-alert-enrichment.py"
  output_path = "${path.module}/.build/cspm-alert-enrichment.zip"
}

resource "aws_iam_role" "cspm_alert_enrichment" {
  name = "${local.name_prefix}-cspm-alert-enrichment-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cspm_alert_enrichment_basic_logs" {
  role       = aws_iam_role.cspm_alert_enrichment.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "cspm_alert_enrichment_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.cspm_alert_dedup.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.slack_app.arn] # 28-ciem-key-exception-flow.tf의 Bot Token 재사용
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/cspm/exception-records:*"]
  }
}

resource "aws_iam_role_policy" "cspm_alert_enrichment_permissions" {
  name   = "cspm-alert-enrichment-permissions"
  role   = aws_iam_role.cspm_alert_enrichment.id
  policy = data.aws_iam_policy_document.cspm_alert_enrichment_permissions.json
}

resource "aws_lambda_function" "cspm_alert_enrichment" {
  function_name    = "${local.name_prefix}-cspm-alert-enrichment"
  role             = aws_iam_role.cspm_alert_enrichment.arn
  handler          = "cspm-alert-enrichment.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename          = data.archive_file.cspm_alert_enrichment.output_path
  source_code_hash = data.archive_file.cspm_alert_enrichment.output_base64sha256

  environment {
    variables = {
      DEDUP_TABLE_NAME          = aws_dynamodb_table.cspm_alert_dedup.name
      SLACK_SECRET_ARN          = aws_secretsmanager_secret.slack_app.arn # 28번 파일의 Bot Token 재사용(chat.update 소유권 일치를 위해)
      SLACK_CHANNEL             = "#cspm-findings"
      AWS_ACCOUNT_ID            = data.aws_caller_identity.current.account_id
      DEDUP_TTL_HOURS           = "24"
      CLOUDTRAIL_LOOKBACK_HOURS = "48"
      CSPM_EXCEPTION_LOG_GROUP  = "/aws/cspm/exception-records"
    }
  }
}

# ---------- EventBridge: CRITICAL/HIGH + ACTIVE + NEW + FAILED만 통과 ----------
resource "aws_cloudwatch_event_rule" "cspm_critical_high_findings" {
  name        = "${local.name_prefix}-cspm-critical-high-findings"
  description = "Security Hub CRITICAL/HIGH, 미해결(NEW), 활성(ACTIVE), 컴플라이언스 실패(FAILED)만 통과"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        Workflow = {
          Status = ["NEW"]
        }
        RecordState = ["ACTIVE"]
        Compliance = {
          Status = ["FAILED"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "cspm_to_lambda" {
  rule = aws_cloudwatch_event_rule.cspm_critical_high_findings.name
  arn  = aws_lambda_function.cspm_alert_enrichment.arn
}

resource "aws_lambda_permission" "allow_eventbridge_cspm_alert" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cspm_alert_enrichment.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cspm_critical_high_findings.arn
}

output "cspm_alert_dedup_table" {
  value = aws_dynamodb_table.cspm_alert_dedup.name
}