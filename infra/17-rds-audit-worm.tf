# =============================================================================
# RDS 감사로그 장기 보관 — ADR-008 원칙 적용 (Object Lock WORM + Glacier 전환)
# =============================================================================
# ADR-008은 CloudTrail/VPC Flow Logs/GuardDuty/Route 53 Resolver 로그를 Security
# Lake(OCSF)로 통합하고 Object Lock으로 위변조를 막는 걸 결정했습니다. RDS
# PostgreSQL 로그는 Security Lake의 네이티브 지원 소스가 아니라서(OCSF 커스텀
# 소스를 직접 만들어야 함 - 별도의 큰 작업) 이번엔 그 통합까지는 하지 않고,
# ADR-008 결정 2/3의 핵심 원칙만 그대로 재사용합니다:
#   - S3 Object Lock(Compliance Mode)으로 보존 기간 동안 위변조/삭제 원천 차단
#   - Glacier Deep Archive로 자동 전환해 장기 보관 비용 최소화
#   - 실시간 조회(CloudWatch, 30일)와 장기 증적(S3 WORM, 1년+)을 분리 운영
#
# 경로: RDS → CloudWatch Logs(06-rds.tf, 30일) → 구독 필터 → Kinesis Data
# Firehose → S3(Object Lock)

# ---------- S3 WORM 버킷 ----------
resource "aws_s3_bucket" "rds_audit_worm" {
  bucket = "${local.name_prefix}-rds-audit-worm-${data.aws_caller_identity.current.account_id}"

  object_lock_enabled = true # 버킷 생성 시에만 설정 가능, 나중에 못 켬
}

# Object Lock은 버저닝이 필수 전제조건
resource "aws_s3_bucket_versioning" "rds_audit_worm" {
  bucket = aws_s3_bucket.rds_audit_worm.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "rds_audit_worm" {
  bucket = aws_s3_bucket.rds_audit_worm.id

  rule {
    default_retention {
      mode = "COMPLIANCE" # 루트 계정 포함 누구도 보존기간 내 삭제/수정 불가 (ADR-008 결정 2)
      days = var.rds_audit_worm_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.rds_audit_worm]
}

resource "aws_s3_bucket_public_access_block" "rds_audit_worm" {
  bucket                  = aws_s3_bucket.rds_audit_worm.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "rds_audit_worm" {
  bucket = aws_s3_bucket.rds_audit_worm.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 30일 경과 후 Glacier Deep Archive로 자동 전환 (ADR-008 결정 3, "최대 95% 절감" 근거와 동일)
resource "aws_s3_bucket_lifecycle_configuration" "rds_audit_worm" {
  bucket = aws_s3_bucket.rds_audit_worm.id

  rule {
    id     = "transition-to-deep-archive"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "DEEP_ARCHIVE"
    }
  }
}

# ---------- Kinesis Data Firehose: CloudWatch Logs → S3 WORM ----------
resource "aws_iam_role" "firehose_rds_audit" {
  name = "${local.name_prefix}-firehose-rds-audit-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "firehose.amazonaws.com" }
    }]
  })
}

data "aws_iam_policy_document" "firehose_rds_audit" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"]
    resources = [aws_s3_bucket.rds_audit_worm.arn, "${aws_s3_bucket.rds_audit_worm.arn}/*"]
  }
}

resource "aws_iam_role_policy" "firehose_rds_audit" {
  name   = "firehose-s3-write"
  role   = aws_iam_role.firehose_rds_audit.id
  policy = data.aws_iam_policy_document.firehose_rds_audit.json
}

resource "aws_kinesis_firehose_delivery_stream" "rds_audit" {
  name        = "${local.name_prefix}-rds-audit-worm-stream"
  destination = "extended_s3"

  # Security Hub Firehose.1(전송 스트림 자체의 저장 암호화) 대응 - 목적지 S3
  # 버킷 암호화(위 aws_s3_bucket_server_side_encryption_configuration)와는
  # 별개 통제임. AWS 관리형 키라 추가 비용 없음.
  server_side_encryption {
    enabled = true
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose_rds_audit.arn
    bucket_arn          = aws_s3_bucket.rds_audit_worm.arn
    prefix              = "rds-postgresql-audit/"
    compression_format  = "GZIP"
    buffering_size      = 5   # MB
    buffering_interval   = 300 # 초 - 5분마다 또는 5MB 쌓이면 S3로 flush
  }
}

# ---------- CloudWatch Logs 구독 필터: rds_postgresql 로그 그룹 → Firehose ----------
resource "aws_iam_role" "cwl_to_firehose" {
  name = "${local.name_prefix}-cwl-to-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

data "aws_iam_policy_document" "cwl_to_firehose" {
  statement {
    effect    = "Allow"
    actions   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
    resources = [aws_kinesis_firehose_delivery_stream.rds_audit.arn]
  }
}

resource "aws_iam_role_policy" "cwl_to_firehose" {
  name   = "cwl-to-firehose-put-record"
  role   = aws_iam_role.cwl_to_firehose.id
  policy = data.aws_iam_policy_document.cwl_to_firehose.json
}

resource "aws_cloudwatch_log_subscription_filter" "rds_audit_to_worm" {
  name           = "${local.name_prefix}-rds-audit-to-worm"
  log_group_name = aws_cloudwatch_log_group.rds_postgresql.name
  # [실제 반복 apply/destroy 테스트에서 발견한 문제 수정] 원래 filter_pattern이
  # ""(전부 전달)로 되어 있어서, employees/change_history 테이블을 아무도 안
  # 건드려도 RDS 엔진 자체의 접속/해제·시동 로그가 전부 이 파이프라인을 타고
  # WORM(Object Lock) 버킷에 쌓였습니다. 그 결과 사람이 아무 것도 안 해도
  # destroy 시점에 그 버킷만 잠긴 채로 남는 문제가 있었습니다.
  # pgAudit이 남기는 감사 로그는 항상 "AUDIT:"로 시작하므로(RDS PostgreSQL
  # 공식 pgAudit 로그 포맷), 이 문자열이 포함된 줄만 통과시켜서 진짜 employees/
  # change_history 테이블 접근 감사 기록만 WORM에 쌓이게 좁힙니다 - 주석에 원래
  # 있던 "pgAudit로 이미 employees 테이블만 로그에 남도록 좁혀둔 상태"라는
  # 의도를 실제 필터 값으로 맞춘 것입니다.
  filter_pattern  = "AUDIT"
  destination_arn = aws_kinesis_firehose_delivery_stream.rds_audit.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn
}

output "rds_audit_worm_bucket" {
  description = "RDS 감사로그 장기 보관용 S3 버킷 (Object Lock Compliance mode)"
  value       = aws_s3_bucket.rds_audit_worm.bucket
}
