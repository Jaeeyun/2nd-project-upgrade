# =============================================================================
# 세션 강제 종료 (NIST 800-207 tenet 6 — "진행 중 신뢰의 지속적 재평가" 보완)
# =============================================================================
# 지금까지는 "발급 시점에 한 번 검증하고 만료까지 유효"인 세션 기반 모델이었다.
# 이 파일은 그 공백(진행 중 세션을 실시간에 가깝게 강제 종료하는 능력)을
# 메운다 - 완전한 지속적 재인증 엔진은 아니지만(그러려면 상시 리스크 스코어링
# 엔진이 필요), 최소한 "위협이 확인되면 그 사람 세션만 정밀 차단"은 가능하게 한다.
#
# 파괴적 조치(정상 사용자도 강제 로그아웃될 수 있음)라 Security Hub Custom
# Action으로 사람이 트리거한다(ADR-005 결정 5, 자동 실행 안 함).

resource "aws_securityhub_action_target" "revoke_session" {
  # (한글: 세션 강제 종료 - 특정 인물의 AWS 세션(8개 Role 전부)과 Keycloak 세션을 동시에 강제 종료)
  name        = "Revoke User Session"
  identifier  = "RevokeUserSession"
  description = "Force-terminate a specific person's AWS sessions (all 8 roles) and Keycloak session at once"
}

data "archive_file" "session_revoke" {
  type        = "zip"
  source_file = "${path.module}/scripts/session-revoke.py"
  output_path = "${path.module}/.build/session-revoke.zip"
}

resource "aws_iam_role" "session_revoke" {
  name = "${local.name_prefix}-session-revoke-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "session_revoke_basic_logs" {
  role       = aws_iam_role.session_revoke.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "session_revoke_permissions" {
  statement {
    effect  = "Allow"
    actions = ["iam:PutRolePolicy"]
    resources = [for name in local.keycloak_role_names : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${name}"]
  }
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/keycloak/${local.name_prefix}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "session_revoke_permissions" {
  name   = "session-revoke-permissions"
  role   = aws_iam_role.session_revoke.id
  policy = data.aws_iam_policy_document.session_revoke_permissions.json
}

resource "aws_iam_role_policy_attachment" "session_revoke_vpc" {
  role       = aws_iam_role.session_revoke.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Keycloak SG는 admin CIDR 전용이라, VPC 미부착 Lambda는 발신지가 AWS 공용
# IP 풀이 되어 관리자 API 접속이 막힌다 - private_app에 붙여서 피어링 사설
# 경로로 Keycloak 사설 IP에 접속한다.
resource "aws_security_group" "session_revoke_lambda" {
  name        = "${local.name_prefix}-session-revoke-lambda-sg"
  description = "session-revoke Lambda - outbound to Keycloak(443) only"
  vpc_id      = aws_vpc.main.id
}

# 핸들러가 제일 먼저 호출하는 ssm.get_parameter()/sns.publish() 같은 AWS
# 서비스 API는 인터넷/NAT 경유라 목적지가 Keycloak VPC(10.1.0.0/16)가 아니다
# - Keycloak용 피어링 443과는 별개로 AWS API용 0.0.0.0/0:443도 필요하다.
resource "aws_vpc_security_group_egress_rule" "session_revoke_lambda_to_internet" {
  security_group_id = aws_security_group.session_revoke_lambda.id
  cidr_ipv4          = "0.0.0.0/0"
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
  description        = "AWS API calls (SSM/SNS) via NAT gateway"
}

resource "aws_vpc_security_group_egress_rule" "session_revoke_lambda_to_keycloak" {
  security_group_id = aws_security_group.session_revoke_lambda.id
  cidr_ipv4          = var.keycloak_vpc_cidr
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
  description        = "Keycloak admin API via VPC peering"
}

resource "aws_lambda_function" "session_revoke" {
  function_name    = "${local.name_prefix}-session-revoke"
  role             = aws_iam_role.session_revoke.arn
  handler          = "session-revoke.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.session_revoke.output_path
  source_code_hash = data.archive_file.session_revoke.output_base64sha256

  vpc_config {
    subnet_ids         = aws_subnet.private_app[*].id
    security_group_ids = [aws_security_group.session_revoke_lambda.id]
  }

  environment {
    variables = {
      NAME_PREFIX      = local.name_prefix
      KEYCLOAK_HOST    = aws_instance.keycloak.private_ip
      REALM_NAME       = var.keycloak_realm_name
      SNS_TOPIC_ARN    = aws_sns_topic.security_alerts.arn
      ROLE_NAMES_JSON  = jsonencode([for name in local.keycloak_role_names : name])
    }
  }
}

resource "aws_cloudwatch_event_rule" "revoke_session_action" {
  name = "${local.name_prefix}-revoke-session-action"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Custom Action"]
    resources   = [aws_securityhub_action_target.revoke_session.arn]
  })
}

resource "aws_cloudwatch_event_target" "revoke_session_lambda" {
  rule = aws_cloudwatch_event_rule.revoke_session_action.name
  arn  = aws_lambda_function.session_revoke.arn
}

resource "aws_lambda_permission" "allow_eventbridge_revoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.session_revoke.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.revoke_session_action.arn
}
