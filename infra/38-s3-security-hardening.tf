# =============================================================================
# S3 버킷 보안 강화 - cloudtrail_bucket/config_bucket 외 나머지 4개 버킷
# =============================================================================
# 08-cloudtrail.tf(cloudtrail_bucket)와 10-security-baseline.tf(config_bucket)는
# 이미 SSL 강제+액세스 로깅이 적용돼 있음. 나머지 rds_audit_worm/session_logs/
# mtls_trust_store 3개 버킷 + config_bucket 자신의 액세스 로그 타겟을 여기서 정리.

# ---------- rds_audit_worm: SSL 강제 + 액세스 로그 ----------
data "aws_iam_policy_document" "rds_audit_worm_ssl" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.rds_audit_worm.arn, "${aws_s3_bucket.rds_audit_worm.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "rds_audit_worm_ssl" {
  bucket = aws_s3_bucket.rds_audit_worm.id
  policy = data.aws_iam_policy_document.rds_audit_worm_ssl.json
}

resource "aws_s3_bucket_logging" "rds_audit_worm" {
  bucket = aws_s3_bucket.rds_audit_worm.id

  target_bucket = aws_s3_bucket.config_bucket.id
  target_prefix = "s3-access-logs/rds-audit-worm/"
}

# ---------- session_logs: SSL 강제 + 액세스 로그 + lifecycle ----------
data "aws_iam_policy_document" "session_logs_ssl" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.session_logs.arn, "${aws_s3_bucket.session_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # config_bucket 자신의 액세스 로그를 여기로 받기 위한 권한(아래 aws_s3_bucket_logging.config_bucket)
  statement {
    sid    = "S3ServerAccessLogsPolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.session_logs.arn}/s3-access-logs/*"]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.config_bucket.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "session_logs_ssl" {
  bucket = aws_s3_bucket.session_logs.id
  policy = data.aws_iam_policy_document.session_logs_ssl.json
}

resource "aws_s3_bucket_logging" "session_logs" {
  bucket = aws_s3_bucket.session_logs.id

  target_bucket = aws_s3_bucket.config_bucket.id
  target_prefix = "s3-access-logs/session-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "session_logs" {
  bucket = aws_s3_bucket.session_logs.id

  rule {
    id     = "expire_after_90_days"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
  }
}

# ---------- config_bucket 자신의 액세스 로그(순환 참조 피하려고 session_logs를 타겟으로) ----------
resource "aws_s3_bucket_logging" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  target_bucket = aws_s3_bucket.session_logs.id
  target_prefix = "s3-access-logs/config-bucket/"
}

# ---------- mtls_trust_store: SSL 강제 + 액세스 로그 + lifecycle ----------
data "aws_iam_policy_document" "mtls_trust_store_ssl" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.mtls_trust_store.arn, "${aws_s3_bucket.mtls_trust_store.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "mtls_trust_store_ssl" {
  bucket = aws_s3_bucket.mtls_trust_store.id
  policy = data.aws_iam_policy_document.mtls_trust_store_ssl.json
}

resource "aws_s3_bucket_logging" "mtls_trust_store" {
  bucket = aws_s3_bucket.mtls_trust_store.id

  target_bucket = aws_s3_bucket.config_bucket.id
  target_prefix = "s3-access-logs/mtls-trust-store/"
}

resource "aws_s3_bucket_lifecycle_configuration" "mtls_trust_store" {
  bucket = aws_s3_bucket.mtls_trust_store.id

  rule {
    id     = "expire_after_90_days"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
  }
}

# =============================================================================
# 계정 레벨 무료 항목: EC2.7(EBS 기본 암호화)
# =============================================================================
resource "aws_ebs_encryption_by_default" "main" {
  enabled = true
}

# [EC2.172 - 의도적으로 미조치] VPC Block Public Access를 켜면 계정/리전
# 전체의 인터넷 게이트웨이 트래픽이 기본 차단된다. 지금 Keycloak/Pomerium
# EC2가 퍼블릭 서브넷에서 실제로 인터넷과 통신 중이고(관리자 CIDR로 제한된
# 인바운드 + 아웃바운드), NAT Gateway도 프라이빗 서브넷의 아웃바운드를
# 담당하고 있어 - VPC별 예외(aws_vpc_block_public_access_exclusion)를 먼저
# 만들지 않고 이걸 켜면 즉시 서비스 장애가 난다. 예외 설정까지 포함해
# 별도로 신중하게 진행해야 하는 작업이라 Track 4(기술부채)로 내림.

# Security Hub IAM.18 대응 - AWS Support 인시던트 관리용 역할(무료, 실제로
# 아무도 assume 안 해도 통제 자체는 "역할 존재 여부"만 확인함)
resource "aws_iam_role" "aws_support_access" {
  name = "${local.name_prefix}-aws-support-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "aws_support_access" {
  role       = aws_iam_role.aws_support_access.name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}
