# =============================================================================
# Amazon Security Lake (ADR-008 본체) + VPC Flow Logs 네이티브 등록 (ADR-015)
# =============================================================================

variable "enable_security_lake" {
  description = "Security Lake(19-security-lake.tf) 활성화 여부."
  type        = bool
  default     = false
}

variable "security_lake_retention_days" {
  description = "Security Lake 데이터 보존기간(일)."
  type        = number
  default     = 365

  validation {
    condition     = var.security_lake_retention_days > 30
    error_message = "security_lake_retention_days는 transition 설정(30일)보다 커야 합니다."
  }
}

# 1. Metastore Manager IAM Role 정의
resource "aws_iam_role" "security_lake_metastore" {
  count = var.enable_security_lake ? 1 : 0
  name  = "${local.name_prefix}-security-lake-metastore-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# 2. 기본 Metastore Manager 관리형 정책 첨부
resource "aws_iam_role_policy_attachment" "security_lake_metastore" {
  count      = var.enable_security_lake ? 1 : 0
  role       = aws_iam_role.security_lake_metastore[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonSecurityLakeMetastoreManager"
}

# 3. LakeFormation:ListPermissions 및 Glue catalog 조회 AccessDenied 방지용 정책 첨부
resource "aws_iam_role_policy_attachment" "security_lake_metastore_lakeformation" {
  count      = var.enable_security_lake ? 1 : 0
  role       = aws_iam_role.security_lake_metastore[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSLakeFormationDataAdmin"
}

# 4. Security Lake Data Lake 생성
resource "aws_securitylake_data_lake" "main" {
  count                       = var.enable_security_lake ? 1 : 0
  meta_store_manager_role_arn = aws_iam_role.security_lake_metastore[0].arn

  configuration {
    region = var.aws_region

    encryption_configuration {
      kms_key_id = "S3_MANAGED_KEY" # 별도 KMS 키 없이 S3 관리형 암호화 사용
    }

    lifecycle_configuration {
      expiration {
        days = var.security_lake_retention_days
      }
      transition {
        days          = 30
        storage_class = "GLACIER"
      }
    }
  }

  # 두 IAM 정책 연결이 완료된 후 Data Lake 생성을 진행함
  depends_on = [
    aws_iam_role_policy_attachment.security_lake_metastore,
    aws_iam_role_policy_attachment.security_lake_metastore_lakeformation
  ]
}

# aws_securitylake_data_lake만으로는 Glue 데이터베이스/테이블 스키마만 생기고
# 실제 로그 수집은 시작되지 않는다(NOT_COLLECTING 상태로 멈춤) -
# aws_securitylake_aws_log_source를 소스별로 명시해야 수집이 시작된다.
# VPC_FLOW/SH_FINDINGS만 켠다: CLOUD_TRAIL_MGMT는 이 계정/리전 조합에서
# 미지원이고, EKS_AUDIT은 클러스터 쪽에 EKS 감사 로그를 Security Lake로
# 보내는 별도 설정이 없어 소스만 켜도 항상 비어있어 제외.
resource "aws_securitylake_aws_log_source" "vpc_flow" {
  count = var.enable_security_lake ? 1 : 0

  source {
    source_name = "VPC_FLOW"
    regions     = [var.aws_region]
  }

  depends_on = [aws_securitylake_data_lake.main]
}

resource "aws_securitylake_aws_log_source" "sh_findings" {
  count = var.enable_security_lake ? 1 : 0

  source {
    source_name = "SH_FINDINGS"
    regions     = [var.aws_region]
  }

  depends_on = [aws_securitylake_data_lake.main]
}

output "security_lake_arn" {
  value = var.enable_security_lake ? aws_securitylake_data_lake.main[0].arn : "disabled (enable_security_lake=false)"
}