# =============================================================================
# CIEM: Access Key 예외 확인 Slack 인터랙티브 플로우 (ADR-017 결정 2)
# =============================================================================
# 24-ciem-lambda.tf의 "Unused Access 월간 요약"과는 별개로, Access Key만 따로
# 더 정교하게 다룬다 - 소유자를 찾아서, 삭제 여부를 사람이 Slack 버튼으로
# 직접 승인하게 한다(자동 삭제 없음).
#
# ⚠️ 사전 준비(수동): Slack App을 만들고 아래를 각각 발급받아 Secrets Manager에
# 채워 넣어야 실제로 동작합니다.
#   - Bot Token(chat:write 권한) → bot_token
#   - Signing Secret(Interactivity 서명 검증용) → signing_secret
#   - Slack App의 Interactivity Request URL을 아래 aws_apigatewayv2_api의
#     출력 엔드포인트로 설정
# 이 값들을 채우기 전까지는 리소스는 생성되지만 실제 알림/콜백은 동작하지 않습니다.

resource "aws_secretsmanager_secret" "slack_app" {
  name        = "${local.name_prefix}-slack-app-credentials"
  description = "Slack Bot Token + Signing Secret (수동으로 값 채워야 함)"

  # 기본값(30일 유예기간)으로 두면 destroy할 때마다 "삭제 예정" 상태로만
  # 남고 즉시 지워지지 않아 바로 다음 apply에서 같은 이름으로 재생성이
  # 실패한다. PoC/반복 테스트 목적이라 즉시 완전 삭제되도록 0으로 둔다 -
  # 실운영 전환 시에는 실수로 지웠을 때 복구할 여유를 위해 7~30일 권장.
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "slack_app" {
  secret_id = aws_secretsmanager_secret.slack_app.id
  secret_string = jsonencode({
    bot_token      = "xoxb-여기에-실제-값을-채우세요"
    signing_secret = "여기에-실제-값을-채우세요"
  })

  lifecycle {
    ignore_changes = [secret_string] # 최초 apply 후 콘솔/CLI로 값 갱신 시 Terraform이 덮어쓰지 않게
  }
}

# ---------- Lambda A: 미사용 키 탐지 + Slack 인터랙티브 메시지 발송 ----------
data "archive_file" "ciem_key_notify" {
  type        = "zip"
  source_file = "${path.module}/scripts/ciem-key-exception-notify.py"
  output_path = "${path.module}/.build/ciem-key-exception-notify.zip"
}

resource "aws_iam_role" "ciem_key_notify" {
  name = "${local.name_prefix}-ciem-key-notify-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ciem_key_notify_basic_logs" {
  role       = aws_iam_role.ciem_key_notify.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "ciem_key_notify_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["iam:ListUsers", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed", "iam:ListUserTags"]
    resources = ["*"] # ListUsers 등은 리소스 레벨 제한 미지원 액션
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.slack_app.arn]
  }
}

resource "aws_iam_role_policy" "ciem_key_notify_permissions" {
  name   = "ciem-key-notify-permissions"
  role   = aws_iam_role.ciem_key_notify.id
  policy = data.aws_iam_policy_document.ciem_key_notify_permissions.json
}

resource "aws_lambda_function" "ciem_key_notify" {
  function_name    = "${local.name_prefix}-ciem-key-exception-notify"
  role             = aws_iam_role.ciem_key_notify.arn
  handler          = "ciem-key-exception-notify.handler"
  runtime          = "python3.12"
  timeout          = 120
  filename         = data.archive_file.ciem_key_notify.output_path
  source_code_hash = data.archive_file.ciem_key_notify.output_base64sha256

  environment {
    variables = {
      SLACK_SECRET_ARN = aws_secretsmanager_secret.slack_app.arn
      SLACK_CHANNEL    = "#cspm-findings"
    }
  }
}

resource "aws_scheduler_schedule" "ciem_key_notify_monthly" {
  name       = "${local.name_prefix}-ciem-key-notify-monthly"
  group_name = "default"

  flexible_time_window { mode = "OFF" }
  schedule_expression          = "cron(0 0 1 * ? *)"
  schedule_expression_timezone = "UTC"

  target {
    arn      = aws_lambda_function.ciem_key_notify.arn
    role_arn = aws_iam_role.ciem_scheduler.arn # 24-ciem-lambda.tf에서 만든 걸 재사용
  }
}

resource "aws_lambda_permission" "allow_scheduler_key_notify" {
  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ciem_key_notify.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.ciem_key_notify_monthly.arn
}

# ---------- Lambda B: Slack 버튼 클릭 콜백 처리 ----------
data "archive_file" "ciem_key_callback" {
  type        = "zip"
  source_file = "${path.module}/scripts/ciem-key-exception-callback.py"
  output_path = "${path.module}/.build/ciem-key-exception-callback.zip"
}

resource "aws_iam_role" "ciem_key_callback" {
  name = "${local.name_prefix}-ciem-key-callback-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ciem_key_callback_basic_logs" {
  role       = aws_iam_role.ciem_key_callback.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "ciem_key_callback_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["iam:TagUser", "iam:UpdateAccessKey", "iam:DeleteAccessKey"]
    resources = ["*"] # 대상이 매번 달라져 와일드카드 - 필요시 특정 User 경로로 좁히는 것도 검토
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.slack_app.arn]
  }
  # ---------- 36-ciem-boundary-drift-check.tf(권한 드리프트) 처리용 추가 권한 ----------
  # 이 콜백 Lambda가 Slack Interactivity의 유일한 수신처(URL 하나만 등록 가능)라
  # 서로 다른 CIEM 알림 종류를 이 Lambda 하나가 다 처리한다 - action_id로 구분.
  statement {
    effect    = "Allow"
    actions   = ["access-analyzer:GetGeneratedPolicy"]
    resources = ["*"]
  }
  statement {
    effect  = "Allow"
    actions = ["iam:ListRolePolicies", "iam:PutRolePolicy", "iam:TagRole"]
    # 8개 SAML Role로만 정확히 좁힘 - 실수로라도 다른 Role을 건드릴 수 없게
    resources = [for name in local.keycloak_role_names : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${name}"]
  }
  # ---------- 44-iam-boundary-violation-watch.tf(경계 위반 1-Click 잠금) 처리용 ----------
  # 잠금 로직을 여기서 새로 구현하지 않고 session-revoke Lambda를 호출만
  # 하므로, 이 Lambda 하나에 대한 InvokeFunction 권한만 있으면 된다.
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.session_revoke.arn]
  }
  # session-revoke는 세션만 차단할 뿐 위반 정책 자체는 못 떼므로, "Lock &
  # Revoke" 버튼이 실제로 위반 정책까지 떼려면 이 권한이 필요하다.
  statement {
    effect    = "Allow"
    actions   = ["iam:DetachRolePolicy"]
    resources = [for name in local.keycloak_role_names : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${name}"]
  }
  # 버튼 클릭 시 같은 event_id로 status=RESOLVED 로그를 남기기 위한 권한
  # (iam-boundary-violation-watch.py가 남긴 UNRESOLVED 로그와 짝지어짐).
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.iam_boundary_violation.arn}:*"]
  }
}

resource "aws_iam_role_policy" "ciem_key_callback_permissions" {
  name   = "ciem-key-callback-permissions"
  role   = aws_iam_role.ciem_key_callback.id
  policy = data.aws_iam_policy_document.ciem_key_callback_permissions.json
}

resource "aws_lambda_function" "ciem_key_callback" {
  function_name    = "${local.name_prefix}-ciem-key-exception-callback"
  role             = aws_iam_role.ciem_key_callback.arn
  handler          = "ciem-key-exception-callback.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.ciem_key_callback.output_path
  source_code_hash = data.archive_file.ciem_key_callback.output_base64sha256

  environment {
    variables = {
      SLACK_SECRET_ARN             = aws_secretsmanager_secret.slack_app.arn
      SESSION_REVOKE_FUNCTION_NAME = aws_lambda_function.session_revoke.function_name
      BOUNDARY_VIOLATION_LOG_GROUP = aws_cloudwatch_log_group.iam_boundary_violation.name
      CSPM_EXCEPTION_LOG_GROUP     = aws_cloudwatch_log_group.cspm_exception_records.name
    }
  }
}

# ---------- API Gateway: Slack Interactivity 콜백 수신 엔드포인트 ----------
resource "aws_apigatewayv2_api" "slack_interactivity" {
  name          = "${local.name_prefix}-slack-interactivity"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "slack_interactivity" {
  api_id                 = aws_apigatewayv2_api.slack_interactivity.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.ciem_key_callback.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "slack_interactivity" {
  api_id    = aws_apigatewayv2_api.slack_interactivity.id
  route_key = "POST /slack/interactivity"
  target    = "integrations/${aws_apigatewayv2_integration.slack_interactivity.id}"
}

resource "aws_cloudwatch_log_group" "slack_interactivity_access_logs" {
  name              = "/aws/apigateway/${local.name_prefix}-slack-interactivity"
  retention_in_days = 30
}

resource "aws_apigatewayv2_stage" "slack_interactivity" {
  api_id      = aws_apigatewayv2_api.slack_interactivity.id
  name        = "$default"
  auto_deploy = true

  # Security Hub APIGateway.9 대응
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.slack_interactivity_access_logs.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }
}

resource "aws_lambda_permission" "allow_apigw_callback" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ciem_key_callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.slack_interactivity.execution_arn}/*/*"
}

output "slack_interactivity_endpoint" {
  description = "Slack App 설정의 Interactivity Request URL에 이 값 + /slack/interactivity 를 넣으세요"
  value       = aws_apigatewayv2_stage.slack_interactivity.invoke_url
}
