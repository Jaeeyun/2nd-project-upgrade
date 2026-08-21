# =============================================================================
# RDS 마스킹 뷰 권한 드리프트 자동 복구 (100-SCENARIOS.md 76번)
# =============================================================================

variable "psycopg2_layer_arn" {
  description = "psycopg2 Lambda Layer ARN. AWS 공식 Layer가 없어 커뮤니티 Layer나 직접 빌드가 필요합니다. apply 전 실제 값으로 채우세요(리전/Python 버전에 맞는 Layer)."
  type        = string
  default     = ""
}

data "archive_file" "rds_view_permission_check" {
  type        = "zip"
  source_file = "${path.module}/scripts/rds-view-permission-check.py"
  output_path = "${path.module}/.build/rds-view-permission-check.zip"
}

resource "aws_iam_role" "rds_view_permission_check" {
  name = "${local.name_prefix}-rds-view-permission-check-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_view_permission_check_basic_logs" {
  role       = aws_iam_role.rds_view_permission_check.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "rds_view_permission_check_vpc" {
  role       = aws_iam_role.rds_view_permission_check.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" # RDS가 VPC 안에 있어 Lambda도 VPC에 붙어야 함
}

data "aws_iam_policy_document" "rds_view_permission_check_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["rds-db:connect"]
    resources = ["arn:aws:rds-db:*:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/remediation_admin"]
  }
}

resource "aws_iam_role_policy" "rds_view_permission_check_permissions" {
  name   = "rds-view-permission-check-permissions"
  role   = aws_iam_role.rds_view_permission_check.id
  policy = data.aws_iam_policy_document.rds_view_permission_check_permissions.json
}

# Lambda를 RDS와 같은 VPC(프라이빗 앱 서브넷)에 붙임 - 격리 서브넷(16번)이 아니라
# private_app을 쓰는 이유: 이 Lambda는 CloudShell처럼 사람이 직접 조작하는 경로가
# 아니라 매일 자동 실행되는 배치라, 격리 서브넷의 "다운로드 방지" 목적과는 무관함
#
# [실제 검증 중 발견 → 설계 변경] 원래는 REVOKE 후 SNS로 직접 알림까지
# 보내려 했는데, 그러려면 이 SG에 443 아웃바운드가 필요했고(SNS는 VPC
# 엔드포인트 없이는 인터넷 경유), 빠뜨렸더니 sns.publish()가 타임아웃으로
# 죽는 문제가 실측으로 발견됐다. SNS를 아예 빼고, "REVOKE했다"는 사실을
# CloudWatch Logs에 구조화된 한 줄로만 남기도록 바꿨다(Lambda 로그는 VPC
# 밖 AWS 내부 경로로 전달되어 이 SG의 아웃바운드 제한과 무관함) - Slack
# 알림은 Grafana 알림 규칙이 그 로그를 감시해서 대신 보낸다
# (scripts/grafana-alerting-setup.sh). 그 결과 이 SG는 RDS(5432) 외에는
# 아무것도 열 필요가 없어졌다.
resource "aws_security_group" "rds_view_permission_check_lambda" {
  name = "${local.name_prefix}-rds-view-check-lambda-sg"
  # (한글: RDS 권한 드리프트 점검 Lambda - RDS(5432)로만 아웃바운드)
  description = "RDS permission drift check Lambda - outbound to RDS(5432) only"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_egress_rule" "rds_view_check_lambda_to_rds" {
  security_group_id            = aws_security_group.rds_view_permission_check_lambda.id
  referenced_security_group_id = aws_security_group.rds_sg.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_lambda_function" "rds_view_permission_check" {
  function_name = "${local.name_prefix}-rds-view-permission-check"
  role          = aws_iam_role.rds_view_permission_check.arn
  handler       = "rds-view-permission-check.handler"
  runtime       = "python3.12"
  # VPC 안 Lambda라 콜드 스타트 때 ENI 연결 자체에 다소 시간이 걸릴 수 있어
  # 기본 3초보다 넉넉하게 잡는다(SNS를 뺀 뒤로는 DB 쿼리+REVOKE만 하므로
  # 60초면 충분함 - 이전엔 SNS 타임아웃 때문에 120초까지 늘렸었음).
  timeout          = 60
  filename         = data.archive_file.rds_view_permission_check.output_path
  source_code_hash = data.archive_file.rds_view_permission_check.output_base64sha256
  layers           = var.psycopg2_layer_arn != "" ? [var.psycopg2_layer_arn] : []

  vpc_config {
    subnet_ids         = aws_subnet.private_app[*].id
    security_group_ids = [aws_security_group.rds_view_permission_check_lambda.id]
  }

  environment {
    variables = {
      DB_HOST = aws_db_instance.main.address
      DB_NAME = aws_db_instance.main.db_name
    }
  }
}

resource "aws_scheduler_schedule" "rds_view_permission_check_daily" {
  name       = "${local.name_prefix}-rds-view-check-daily"
  group_name = "default"

  flexible_time_window { mode = "OFF" }
  schedule_expression          = "cron(0 18 * * ? *)" # 매일 03:00 KST
  schedule_expression_timezone = "UTC"

  target {
    arn      = aws_lambda_function.rds_view_permission_check.arn
    role_arn = aws_iam_role.ciem_scheduler.arn # 24-ciem-lambda.tf의 스케줄러 Role 재사용
  }
}

resource "aws_lambda_permission" "allow_scheduler_rds_check" {
  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rds_view_permission_check.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.rds_view_permission_check_daily.arn
}
