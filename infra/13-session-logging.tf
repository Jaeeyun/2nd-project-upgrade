# =============================================================================
# Session Manager 세션 로깅 (ADR-002 결정 5)
# =============================================================================
# Session Manager Preferences는 기본적으로 로깅이 꺼져있다. S3+CloudWatch 로깅을
# SSM-SessionManagerRunShell 커스텀 문서로 강제 활성화한다. 이 문서 이름은
# policies/03,04,06의 AllowSSMSessionDocument가 그대로 참조하므로(ADR-002 결정 6)
# 반드시 "SSM-SessionManagerRunShell"을 유지해야 한다.

resource "aws_s3_bucket" "session_logs" {
  bucket        = "${local.name_prefix}-ssm-session-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "session_logs" {
  bucket                  = aws_s3_bucket.session_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "session_logs" {
  bucket = aws_s3_bucket.session_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_cloudwatch_log_group" "session_logs" {
  name              = "/ssm/${local.name_prefix}/session-logs"
  retention_in_days = 90
}

resource "aws_ssm_document" "session_manager_prefs" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "ADR-002 decision 5: S3+CloudWatch session logging enforced"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName            = aws_s3_bucket.session_logs.bucket
      s3EncryptionEnabled     = true
      s3KeyPrefix              = "sessions/"
      cloudWatchLogGroupName  = aws_cloudwatch_log_group.session_logs.name
      # PoC 단계: 로그 그룹에 KMS 키를 연결하지 않아 false로 맞춤(true로 두면
      # "encryption is not set up" 오류로 세션 시작이 거부됨 - README 표 참고).
      # 정식 운영 시 KMS 키를 만들어 로그 그룹에 연결한 뒤 true로 전환할 것.
      cloudWatchEncryptionEnabled = false
      cloudWatchStreamingEnabled  = true
      idleSessionTimeout          = "20"
    }
  })
}

# 접속 "대상"이 되는 EC2 자신의 IAM Role에도 이 권한이 필요하다(누가 접속하는지와
# 무관 - Session Manager가 세션 시작 전 대상 인스턴스 쪽에서 로그 버킷 암호화
# 설정을 확인하고, 실제로 로그를 써야 하기 때문). SSM 접속 대상인 keycloak EC2와
# EKS 워커 노드 양쪽에 동일하게 붙인다.
data "aws_iam_policy_document" "session_log_bucket_encryption_check" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetEncryptionConfiguration"]
    resources = [aws_s3_bucket.session_logs.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.session_logs.arn}/sessions/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["*"] # 리소스 레벨 제한을 지원하지 않는 액션 (AWS IAM 액션 참조 기준)
  }

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      aws_cloudwatch_log_group.session_logs.arn,
      "${aws_cloudwatch_log_group.session_logs.arn}:*",
    ]
  }
}

resource "aws_iam_role_policy" "keycloak_session_log_bucket_check" {
  name   = "session-log-bucket-encryption-check"
  role   = aws_iam_role.keycloak_ec2.id
  policy = data.aws_iam_policy_document.session_log_bucket_encryption_check.json
}

# EKS 워커 노드도 SSM 접속 대상이라(04-eks.tf에서 AmazonSSMManagedInstanceCore
# 추가) 동일하게 필요. test-target(ABAC 테스트용, 실제 인프라엔 불필요)은 제거함.
resource "aws_iam_role_policy" "eks_node_session_log_bucket_check" {
  name   = "session-log-bucket-encryption-check"
  role   = aws_iam_role.eks_node_role.id
  policy = data.aws_iam_policy_document.session_log_bucket_encryption_check.json
}

# SSM Session Manager는 세션 로깅용 S3 버킷의 암호화 설정을 접속 대상
# 인스턴스의 Role 권한으로 검증하므로, SSM 접속 대상인 Pomerium EC2
# (33-pomerium.tf)의 Role에도 이 권한이 있어야 세션을 시작할 수 있다.
resource "aws_iam_role_policy" "pomerium_session_log_bucket_check" {
  name   = "session-log-bucket-encryption-check"
  role   = aws_iam_role.pomerium_ec2.id
  policy = data.aws_iam_policy_document.session_log_bucket_encryption_check.json
}

output "session_log_bucket" {
  value = aws_s3_bucket.session_logs.bucket
}

output "session_log_group" {
  value = aws_cloudwatch_log_group.session_logs.name
}
