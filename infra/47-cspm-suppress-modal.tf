# =============================================================================
# CSPM: Slack 모달 기반 수동 예외(Suppress) 등록 - 감사 추적 남기기
# =============================================================================
# 45번 파일의 [🛑 위험 수용 / 예외 등록] 버튼 클릭을 처리하는 로직은
# scripts/ciem-key-exception-callback.py(28번 파일 소유 Lambda)에 이미
# 통합했다 - Slack App의 Interactivity Request URL이 앱 전체에 하나뿐이라
# 새 Lambda/API Gateway를 또 만들 필요가 없고, views.open/chat.update에
# 필요한 Bot Token도 28번 파일의 aws_secretsmanager_secret.slack_app을
# 그대로 재사용한다. 이 파일은 그 Lambda에 "추가로" 필요한 권한과 로그
# 그룹만 덧붙인다(기존 aws_iam_role_policy.ciem_key_callback_permissions는
# 건드리지 않고 별도 정책으로 추가 - 관심사 분리).

resource "aws_cloudwatch_log_group" "cspm_exception_records" {
  name              = "/aws/cspm/exception-records"
  retention_in_days = 90 # 예외 승인 감사 기록이라 다른 로그 그룹(30일)보다 길게 보관
}

data "aws_iam_policy_document" "cspm_suppress_modal_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["securityhub:BatchUpdateFindings"]
    resources = ["*"] # Finding ARN이 매번 달라져 리소스 레벨로 못 좁힘(서비스 자체 제약)
  }
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cspm_exception_records.arn}:*"]
  }
}

resource "aws_iam_role_policy" "cspm_suppress_modal_permissions" {
  name   = "cspm-suppress-modal-permissions"
  role   = aws_iam_role.ciem_key_callback.id # 28-ciem-key-exception-flow.tf에서 만든 콜백 Lambda 역할 재사용
  policy = data.aws_iam_policy_document.cspm_suppress_modal_permissions.json
}

output "cspm_exception_records_log_group" {
  value = aws_cloudwatch_log_group.cspm_exception_records.name
}

# 1. 동기화 Lambda 함수 정의
data "archive_file" "cspm_reconciler" {
  type        = "zip"
  source_file = "${path.module}/scripts/cspm-exception-reconciler.py"
  output_path = "${path.module}/.build/cspm-exception-reconciler.zip"
}

resource "aws_lambda_function" "cspm_reconciler" {
  function_name    = "${local.name_prefix}-cspm-exception-reconciler"
  runtime          = "python3.12" # 프로젝트 내 다른 Lambda와 버전 통일
  handler          = "cspm-exception-reconciler.handler"
  filename         = data.archive_file.cspm_reconciler.output_path
  source_code_hash = data.archive_file.cspm_reconciler.output_base64sha256
  role             = aws_iam_role.cspm_reconciler_role.arn
  timeout          = 60

  environment {
    variables = {
      CSPM_EXCEPTION_LOG_GROUP  = aws_cloudwatch_log_group.cspm_exception_records.name
      DUE_SOON_THRESHOLD_DAYS   = "3" # 재검토일 D-3부터 Grafana "만료 관리" 패널에 노출
    }
  }
}

# 2. 실행 스케줄러 (매일 1회 실행)
resource "aws_scheduler_schedule" "cspm_reconciliation" {
  name       = "cspm-exception-reconciler-daily"
  group_name = "default"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "cron(0 18 * * ? *)" # KST 03:00

  target {
    arn      = aws_lambda_function.cspm_reconciler.arn
    role_arn = aws_iam_role.scheduler_invoke_role.arn
  }
}

# ---------- Reconciler Lambda용 IAM Role ----------
resource "aws_iam_role" "cspm_reconciler_role" {
  name = "${local.name_prefix}-cspm-reconciler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cspm_reconciler_basic_logs" {
  role       = aws_iam_role.cspm_reconciler_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "cspm_reconciler_permissions" {
  # Security Hub Finding 상태 조회 권한 - BatchGetFindings는 실제로 존재하지
  # 않는 API라서(라이브 테스트로 확인) GetFindings(Id 필터)만 필요하다.
  statement {
    effect    = "Allow"
    actions   = ["securityhub:GetFindings"]
    resources = ["*"]
  }
  # CloudWatch Logs 쿼리 실행 및 결과 조회 권한
  statement {
    effect = "Allow"
    actions = [
      "logs:StartQuery",
      "logs:GetQueryResults",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/cspm/exception-records:*"
    ]
  }
}

resource "aws_iam_role_policy" "cspm_reconciler_permissions" {
  name   = "cspm-reconciler-permissions"
  role   = aws_iam_role.cspm_reconciler_role.id
  policy = data.aws_iam_policy_document.cspm_reconciler_permissions.json
}

# ---------- EventBridge Scheduler용 IAM Role ----------
resource "aws_iam_role" "scheduler_invoke_role" {
  name = "${local.name_prefix}-scheduler-cspm-reconciler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "scheduler.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler_invoke_permissions" {
  name = "scheduler-invoke-lambda"
  role = aws_iam_role.scheduler_invoke_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = [aws_lambda_function.cspm_reconciler.arn]
    }]
  })
}