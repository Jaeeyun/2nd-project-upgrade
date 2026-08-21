# =============================================================================
# CIEM 자동화: 매월 Unused Access 분석 (ADR-007 결정 4, ADR-016)
# =============================================================================

# ---------- IAM Access Analyzer (Unused Access 분석 타입) ----------
resource "aws_accessanalyzer_analyzer" "unused_access" {
  analyzer_name = "${local.name_prefix}-unused-access-analyzer"
  type          = "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = 90 # 90일 이상 미사용 권한을 탐지 대상으로
    }
  }
}

# ---------- Lambda 패키징 ----------
data "archive_file" "ciem_lambda" {
  type        = "zip"
  source_file = "${path.module}/scripts/ciem-unused-access-report.py"
  output_path = "${path.module}/.build/ciem-unused-access-report.zip"
}

# ---------- Lambda 실행 역할 (ADR-011 결정 5: 전용 최소권한) ----------
resource "aws_iam_role" "ciem_lambda" {
  name = "${local.name_prefix}-ciem-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ciem_lambda_basic_logs" {
  role       = aws_iam_role.ciem_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "ciem_lambda_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["access-analyzer:ListFindingsV2", "access-analyzer:GetAnalyzer"]
    resources = [aws_accessanalyzer_analyzer.unused_access.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "ciem_lambda_permissions" {
  name   = "ciem-lambda-permissions"
  role   = aws_iam_role.ciem_lambda.id
  policy = data.aws_iam_policy_document.ciem_lambda_permissions.json
}

resource "aws_lambda_function" "ciem_unused_access_report" {
  function_name    = "${local.name_prefix}-ciem-unused-access-report"
  role             = aws_iam_role.ciem_lambda.arn
  handler          = "ciem-unused-access-report.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.ciem_lambda.output_path
  source_code_hash = data.archive_file.ciem_lambda.output_base64sha256

  environment {
    variables = {
      ANALYZER_ARN  = aws_accessanalyzer_analyzer.unused_access.arn
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }
}

# ---------- 매월 1일 09:00(KST) 트리거 ----------
resource "aws_scheduler_schedule" "ciem_monthly" {
  name       = "${local.name_prefix}-ciem-monthly-report"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = "cron(0 0 1 * ? *)" # 매월 1일 00:00 UTC = 09:00 KST
  schedule_expression_timezone = "UTC"

  target {
    arn      = aws_lambda_function.ciem_unused_access_report.arn
    role_arn = aws_iam_role.ciem_scheduler.arn
  }
}

resource "aws_iam_role" "ciem_scheduler" {
  name = "${local.name_prefix}-ciem-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "scheduler.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ciem_scheduler_invoke" {
  name = "invoke-ciem-lambda"
  role = aws_iam_role.ciem_scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.ciem_unused_access_report.arn
    }]
  })
}

resource "aws_lambda_permission" "allow_scheduler" {
  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ciem_unused_access_report.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.ciem_monthly.arn
}
