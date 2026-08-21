# =============================================================================
# 계정 보안 베이스라인 (ADR-004: AWS Foundational Security Best Practices 정렬)
# =============================================================================
# ADR-004에서 결정한 항목 중 이 저장소(Terraform)로 구현 가능한 부분만 반영합니다.
#
# 이 파일에서 다루는 것:
#   - 결정 1: Security Hub CSPM + FSBP 표준 (CIS는 var.enable_cis_benchmark로 선택)
#   - 결정 2: AWS Config 활성화
#   - 결정 4: 계정 단위 S3 Block Public Access
#   - 결정 6: Budgets 월 예산 알림(80%) + Cost Anomaly Detection
#
# 이 파일에서 다루지 않는 것 (ADR-004 본문 참고):
#   - 결정 3(루트/IAM 사용자 MFA 필수화): 루트 계정 MFA 등록은 콘솔에서 사람이 직접
#     해야 하는 작업이라 Terraform으로 강제할 수 없습니다. IAM 사용자 MFA 강제용
#     정책(require_mfa)은 이 파일 아래쪽에 "준비만" 해뒀습니다 - 이 저장소는 사람의
#     AWS 접근을 ADR-001(SAML/임시자격증명)로 처리하고 있어 현재 attach할
#     IAM 사용자가 없습니다. 예외적으로 IAM 사용자가 생기면 그때 attach하세요.
#   - 결정 5(CloudTrail 전 리전+무결성검증): 08-cloudtrail.tf에 이미 구현되어 있음.
#   - 결정 7(장기 Access Key 금지): 위와 같은 이유로 발급 대상 IAM 사용자가 없어
#     별도 리소스 불필요.
#   - 결정 8(GuardDuty): ADR-003 소관이며 이 저장소엔 아직 리소스가 없음. 필요시 별도 작업.

# -----------------------------------------------------------------------
# AWS Config
# -----------------------------------------------------------------------
# 리소스 설정 변경 이력을 추적하고, Security Hub CSPM 통제 판정의 근거로 씁니다.

resource "aws_s3_bucket" "config_bucket" {
  bucket        = "${local.name_prefix}-config-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_lifecycle_configuration" "config_bucket_lifecycle" {
  bucket = aws_s3_bucket.config_bucket.id

  rule {
    id     = "expire_after_90_days"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }
  }
}

data "aws_iam_policy_document" "config_bucket_policy" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketExistenceCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.config_bucket.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # 08-cloudtrail.tf의 cloudtrail_bucket 액세스 로그를 여기로 받기 위한 S3 로그 전달
  # 서비스 권한(Security Hub S3.9 대응) - ACL 기반 log-delivery-write는 이 프로젝트
  # 전체가 Block Public Access + ACL 비활성 기조라 안 쓰고, 최신 방식인 버킷
  # 정책 기반(logging.s3.amazonaws.com 서비스 프린시펄)으로 부여.
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_bucket.arn}/s3-access-logs/*"]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      # Security Hub S3.9 대응 확장 - cloudtrail_bucket 외 rds_audit_worm/
      # session_logs/mtls_trust_store 버킷의 액세스 로그도 여기로 받음(38-s3-security-hardening.tf)
      values = [
        aws_s3_bucket.cloudtrail_bucket.arn,
        aws_s3_bucket.rds_audit_worm.arn,
        aws_s3_bucket.session_logs.arn,
        aws_s3_bucket.mtls_trust_store.arn,
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Security Hub S3.5 대응 - config_bucket 자체도 SSL 강제
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config_bucket.arn, "${aws_s3_bucket.config_bucket.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_bucket_policy" {
  bucket = aws_s3_bucket.config_bucket.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

# [Security Hub Config.1 대응] 원래 커스텀 IAM Role(AWS_ConfigRole 관리형
# 정책을 붙인 자체 Role)을 썼으나, Config.1 통제가 정확히 "AWS 서비스 연결
# 역할(Service-Linked Role) 사용"만을 요구한다는 걸 확인해 서비스 연결
# 역할로 교체함 - 커스텀 Role보다 권한 범위가 AWS가 직접 관리하는 만큼 더
# 엄격하게 고정되고, AWS 쪽에서 이 Role 삭제도 실제 Config 리소스가 없을
# 때만 허용해 오남용 여지가 적음.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name_prefix}-config-recorder"
  role_arn = aws_iam_service_linked_role.config.arn

  # 나머지 리소스 타입은 전부 기록하되(all_supported=false + EXCLUSION 전략은
  # "명시한 것만 빼고 나머지 전부"라는 뜻), Auto Scaling/ECS Task처럼 변경이
  # 잦아 Configuration Item 건수(=과금 단위)를 폭증시키는 타입만 제외한다.
  # EKS managed node group이 내부적으로 ASG를 쓰므로 이 프로젝트에 실제로
  # 해당하는 항목이다 - 노드가 스케일링될 때마다 CI가 계속 쌓이는 걸 방지.
  # include_global_resource_types는 EXCLUSION_BY_RESOURCE_TYPES 전략과 같이
  # 쓸 수 없다(AWS Config API가 InvalidRecordingGroupException으로 거부함) -
  # 레거시 ALL_SUPPORTED_RESOURCE_TYPES 전략 전용 필드. Exclusion 전략에서는
  # 제외 목록에 없는 한 글로벌 리소스 타입(IAM 등)도 자동으로 계속 기록된다.
  recording_group {
    all_supported = false

    recording_strategy {
      use_only = "EXCLUSION_BY_RESOURCE_TYPES"
    }

    exclusion_by_resource_types {
      resource_types = [
        "AWS::AutoScaling::AutoScalingGroup",
        "AWS::AutoScaling::LaunchConfiguration",
        "AWS::EC2::LaunchTemplate", # 노드그룹 교체마다(이번 세션에서도 여러 번 있었음) 새로 생김
        "AWS::ECS::TaskDefinition",
        "AWS::ECS::Service",
      ]
    }
  }

  depends_on = [aws_iam_service_linked_role.config]
}

resource "aws_config_delivery_channel" "main" {
  name           = "${local.name_prefix}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_bucket.id

  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config_bucket_policy,
  ]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# -----------------------------------------------------------------------
# Security Hub CSPM (FSBP 기본 활성화, CIS는 선택)
# -----------------------------------------------------------------------
# enable_default_standards = false로 두는 이유: 기본값(true)은 FSBP와 CIS를
# 한꺼번에 켜버리는데, ADR-004는 "FSBP를 베이스라인으로 우선하고 CIS는 감사
# 증적이 별도로 요구될 때만 추가"라고 결정했습니다. 그래서 표준을 각각
# 명시적으로 구독(subscribe)하는 방식으로 제어합니다.

resource "aws_securityhub_account" "main" {
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  count = var.enable_cis_benchmark ? 1 : 0

  standards_arn = "arn:aws:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# -----------------------------------------------------------------------
# 계정 단위 S3 Block Public Access
# -----------------------------------------------------------------------
# 개별 버킷 설정 실수와 무관하게, 계정 레벨에서 퍼블릭 노출을 원천 차단합니다.

resource "aws_s3_account_public_access_block" "main" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Security Hub EC2.182 대응 - 이 계정 리전에서 EBS 스냅샷이 실수로라도
# 퍼블릭 공유되는 걸 계정 레벨에서 원천 차단(무료, 이 프로젝트가 스냅샷을
# 직접 만들지 않아도 계정 전체에 적용되는 예방 통제).
resource "aws_ebs_snapshot_block_public_access" "main" {
  state = "block-all-sharing"
}

# -----------------------------------------------------------------------
# Budgets: 월 예산 알림 (80% 도달 시 이메일)
# -----------------------------------------------------------------------

resource "aws_budgets_budget" "monthly_cost" {
  name         = "${local.name_prefix}-monthly-budget"
  budget_type  = "COST"
  limit_amount = var.monthly_budget_amount
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}

# -----------------------------------------------------------------------
# Cost Anomaly Detection: 계정 탈취로 인한 비정상 리소스 생성 조기 포착
# -----------------------------------------------------------------------

resource "aws_ce_anomaly_monitor" "service_monitor" {
  name              = "${local.name_prefix}-service-cost-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

resource "aws_ce_anomaly_subscription" "main" {
  name             = "${local.name_prefix}-cost-anomaly-subscription"
  frequency        = "DAILY"
  monitor_arn_list = [aws_ce_anomaly_monitor.service_monitor.arn]

  subscriber {
    type    = "EMAIL"
    address = var.alert_email
  }

  # 이상 비용 영향(절대값)이 100 USD 이상이면 알림 (대량 GPU 인스턴스 기동 등 탐지 목적)
  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      values        = ["100"]
      match_options = ["GREATER_THAN_OR_EQUAL"]
    }
  }
}

# -----------------------------------------------------------------------
# (준비만 해둠) IAM 사용자 MFA 강제 정책
# -----------------------------------------------------------------------
# 현재 이 저장소는 aws_iam_user를 관리하지 않으므로(사람 접근은 ADR-001의
# SAML/임시자격증명 경로) 아무 곳에도 attach하지 않습니다. 예외적으로 IAM
# 사용자를 만들어야 하는 상황이 생기면, 해당 사용자/그룹에 이 정책을
# attach해서 "자신의 MFA 등록 관련 작업 외에는 MFA 인증 전까지 아무것도
# 못 하게" 강제하세요.

data "aws_iam_policy_document" "require_mfa" {
  statement {
    sid       = "AllowViewAccountInfo"
    effect    = "Allow"
    actions   = ["iam:GetAccountPasswordPolicy", "iam:ListVirtualMFADevices", "iam:GetAccountSummary"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowManageOwnMFA"
    effect = "Allow"
    actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:DeactivateMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:ListMFADevices",
      "iam:GetUser",
      "iam:ChangePassword",
    ]
    resources = [
      "arn:aws:iam::*:mfa/$${aws:username}",
      "arn:aws:iam::*:user/$${aws:username}",
    ]
  }

  statement {
    sid    = "DenyAllExceptMFAManagementUnlessMFAAuthenticated"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken",
    ]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "require_mfa" {
  name        = "${local.name_prefix}-require-mfa"
  description = "MFA authenticated before any action except own MFA setup (currently unattached - see comment above)"
  policy      = data.aws_iam_policy_document.require_mfa.json
}

# -----------------------------------------------------------------------
# IAM 계정 패스워드 정책 (Security Hub IAM.7 대응)
# -----------------------------------------------------------------------
# 위 require_mfa와 같은 이유로 이 계정엔 현재 IAM 사용자가 없지만(사람 접근은
# ADR-001 SAML), Security Hub IAM.7은 "IAM 사용자가 없어도" 계정 패스워드
# 정책 자체가 강한 기준으로 설정돼 있는지를 검사하는 계정 레벨 통제라 여기서
# 미리 강하게 설정해 둡니다(AWS FSBP 권장값: 최소 14자, 대소문자/숫자/특수문자
# 포함, 90일 만료, 최근 24개 재사용 금지).
resource "aws_iam_account_password_policy" "main" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# -----------------------------------------------------------------------
# 계정 보안 연락처 (Security Hub Account.1 대응)
# -----------------------------------------------------------------------
# destroy/apply를 반복해도 유실되지 않도록 값 전체를 terraform.tfvars에서
# 관리(security_contact_name/phone) - alert_email은 이미 있는 값을 재사용.
resource "aws_account_alternate_contact" "security" {
  alternate_contact_type = "SECURITY"
  email_address           = var.alert_email
  name                    = var.security_contact_name
  phone_number            = var.security_contact_phone
  title                   = "Security Administrator"
}
