# =============================================================================
# CIEM: 권한 드리프트 감지 + Slack 승인 기반 정책 최소화 (사용자 요청, ADR-007 확장)
# =============================================================================
# 24-ciem-lambda.tf(월간 Unused Access 리포트)보다 훨씬 짧은 주기로, 지정한
# SAML Role들이 실제로 어떤 API를 썼는지 IAM Access Analyzer Policy Generation
# 으로 분석하고, 안 쓴 권한이 있으면 Slack으로 알린다. 28-ciem-key-exception-
# flow.tf의 "발견은 자동, 실행은 사람 승인 후" 패턴을 그대로 재사용한다 -
# 자동으로 권한을 빼지 않는다(ADR-005 결정 5, 100-SCENARIOS.md 82번 시나리오).
#
# ⚠️ boundary_drift_lookback_hours 기본값(3시간)은 데모/테스트용입니다. 실제
# 운영 전환 시에는 24-ciem-lambda.tf의 90일 기준처럼 훨씬 긴 관찰 기간으로
# 늘리는 걸 강력히 권장합니다 - 그렇지 않으면 분기별/저빈도 정당 업무 권한이
# "미사용"으로 계속 오탐되어 Slack 알림 피로도만 높아집니다.
#
# 사전 조건: 28-ciem-key-exception-flow.tf와 동일한 Slack App 설정
# (aws_secretsmanager_secret.slack_app에 Bot Token/Signing Secret)이 필요합니다.
# 이미 그 파일에서 만든 Secret과 API Gateway를 그대로 재사용합니다.

variable "boundary_drift_lookback_hours" {
  description = "권한 드리프트 검사 시 CloudTrail을 몇 시간 거슬러 볼지. 기본값(3)은 데모/테스트 전용 - 실운영에서는 훨씬 길게(최소 몇 주) 설정할 것을 권장."
  type        = number
  default     = 3
}

variable "boundary_drift_role_suffixes" {
  description = "권한 드리프트 검사 대상 Role 목록(local.keycloak_role_names의 key). security-auditor는 의도적으로 광범위한 읽기전용 권한이 목적이라 기본 검사 대상에서 제외."
  type        = list(string)
  default     = ["dev-general", "dev-lead", "dev-hr-backend", "db-general", "db-lead", "ops-general", "ops-lead"]
}

# access_analyzer.start_policy_generation의 cloudTrailDetails.accessRole은
# 필수 파라미터다 - Access Analyzer 서비스가 우리 CloudTrail S3 버킷을 읽을
# 때 assume할 전용 Role을 만든다.
resource "aws_iam_role" "access_analyzer_cloudtrail_read" {
  name = "${local.name_prefix}-access-analyzer-cloudtrail-read-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "access-analyzer.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "access_analyzer_cloudtrail_read" {
  name = "cloudtrail-bucket-read"
  role = aws_iam_role.access_analyzer_cloudtrail_read.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"]
        Resource = [aws_s3_bucket.cloudtrail_bucket.arn, "${aws_s3_bucket.cloudtrail_bucket.arn}/*"]
      },
      {
        # StartPolicyGeneration은 accessRole을 assume한 뒤 내부적으로
        # cloudtrail:GetTrail도 호출해 트레일 메타데이터를 확인하므로,
        # S3 읽기 권한만으로는 부족하다.
        Effect   = "Allow"
        Action   = ["cloudtrail:GetTrail", "cloudtrail:GetTrailStatus"]
        Resource = [aws_cloudtrail.main.arn]
      },
      {
        # AWS 공식 access-analyzer-policy-generation 서비스 Role 예시 정책에
        # 명시된 두 액션 - last accessed 정보 생성/조회에 필요.
        Effect   = "Allow"
        Action   = ["iam:GetServiceLastAccessedDetails", "iam:GenerateServiceLastAccessedDetails"]
        Resource = "*"
      },
      {
        # [실제 검증 중 발견] S3 읽기 권한만으로는 부족했다 - CloudTrail
        # 버킷 객체가 KMS로 암호화돼 있어서(08-cloudtrail.tf), 이 Role도
        # kms:Decrypt가 없으면 Policy Generation 작업이
        # "AUTHORIZATION_ERROR: Incorrect permissions assigned to access
        # CloudTrail S3 bucket"으로 실패한다(S3 GetObject 자체는 허용돼도
        # 그 객체를 실제로 복호화할 권한이 없었던 것).
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [aws_kms_key.cloudtrail.arn]
      }
    ]
  })
}

# ---------- Lambda A: 드리프트 감지 + Slack 알림 ----------
data "archive_file" "ciem_boundary_drift_notify" {
  type        = "zip"
  source_file = "${path.module}/scripts/ciem-boundary-drift-notify.py"
  output_path = "${path.module}/.build/ciem-boundary-drift-notify.zip"
}

resource "aws_iam_role" "ciem_boundary_drift_notify" {
  name = "${local.name_prefix}-ciem-boundary-drift-notify-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ciem_boundary_drift_notify_basic_logs" {
  role       = aws_iam_role.ciem_boundary_drift_notify.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "ciem_boundary_drift_notify_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["access-analyzer:StartPolicyGeneration", "access-analyzer:GetGeneratedPolicy"]
    resources = ["*"] # Policy Generation Job은 리소스 레벨 제한을 지원하지 않는 액션
  }
  statement {
    effect    = "Allow"
    actions   = ["iam:ListRolePolicies", "iam:GetRolePolicy"]
    resources = [for name in local.keycloak_role_names : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${name}"]
  }
  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.slack_app.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.access_analyzer_cloudtrail_read.arn]
  }
}

resource "aws_iam_role_policy" "ciem_boundary_drift_notify_permissions" {
  name   = "ciem-boundary-drift-notify-permissions"
  role   = aws_iam_role.ciem_boundary_drift_notify.id
  policy = data.aws_iam_policy_document.ciem_boundary_drift_notify_permissions.json
}

resource "aws_lambda_function" "ciem_boundary_drift_notify" {
  function_name    = "${local.name_prefix}-ciem-boundary-drift-notify"
  role             = aws_iam_role.ciem_boundary_drift_notify.arn
  handler          = "ciem-boundary-drift-notify.handler"
  runtime          = "python3.12"
  timeout          = 540 # Policy Generation 대기시간(최대 420초) + 여유
  filename         = data.archive_file.ciem_boundary_drift_notify.output_path
  source_code_hash = data.archive_file.ciem_boundary_drift_notify.output_base64sha256

  environment {
    variables = {
      NAME_PREFIX              = local.name_prefix
      CLOUDTRAIL_ARN           = aws_cloudtrail.main.arn
      LOOKBACK_HOURS           = tostring(var.boundary_drift_lookback_hours)
      ACCESS_ANALYZER_ROLE_ARN = aws_iam_role.access_analyzer_cloudtrail_read.arn
      SLACK_SECRET_ARN         = aws_secretsmanager_secret.slack_app.arn
      SLACK_CHANNEL            = "#cspm-findings"
    }
  }
}

# ---------- Role별로 별도 스케줄 (Lambda 하나가 여러 Role을 순서대로 처리하다
# 타임아웃 나는 걸 방지 - 각 호출은 Role 하나만 담당) ----------
resource "aws_scheduler_schedule" "ciem_boundary_drift_check" {
  for_each = toset(var.boundary_drift_role_suffixes)

  name       = "${local.name_prefix}-boundary-drift-${each.key}"
  group_name = "default"

  flexible_time_window { mode = "OFF" }
  schedule_expression          = "rate(${var.boundary_drift_lookback_hours} hours)"
  schedule_expression_timezone = "UTC"

  target {
    arn      = aws_lambda_function.ciem_boundary_drift_notify.arn
    role_arn = aws_iam_role.ciem_scheduler.arn # 24-ciem-lambda.tf의 스케줄러 Role 재사용
    input    = jsonencode({ role_suffix = each.key })
  }
}

resource "aws_lambda_permission" "allow_scheduler_boundary_drift" {
  for_each = toset(var.boundary_drift_role_suffixes)

  statement_id  = "AllowEventBridgeScheduler-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ciem_boundary_drift_notify.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.ciem_boundary_drift_check[each.key].arn
}

# ---------- Slack 버튼 클릭 콜백은 별도로 안 만듭니다 ----------
# Slack App은 Interactivity Request URL을 앱 전체에 하나만 등록할 수 있습니다.
# 그래서 여기서 별도 콜백 Lambda/API Gateway 라우트를 새로 만드는 대신,
# 28-ciem-key-exception-flow.tf가 이미 등록해둔 aws_lambda_function.ciem_key_callback
# 하나가 action_id로 구분해서 이 알림의 버튼 클릭까지 같이 처리합니다
# (scripts/ciem-key-exception-callback.py의 apply_reduced_policy/keep_current_policy
# 처리 부분 참고). Slack App의 Interactivity Request URL도 28번의
# slack_interactivity_endpoint 값을 그대로 쓰면 됩니다 - 이 파일에서 추가로
# 설정할 URL이 따로 없습니다.

