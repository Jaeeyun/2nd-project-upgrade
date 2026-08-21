# =============================================================================
# AWS Config 관리형 규칙 (ADR-012 결정 7, ADR-017 결정 1)
# =============================================================================
# FSBP(10-security-baseline.tf)가 대부분의 IAM/SG 위생을 이미 커버하지만,
# "명시적으로 켜져 있는지"를 이 프로젝트 코드에서 직접 확인할 수 있게
# 별도로 선언한다. FSBP와 중복 평가되어도 문제 없음(같은 리소스를 두 표준이
# 각자 평가하는 것뿐).

resource "aws_config_config_rule" "restricted_ssh" {
  name = "${local.name_prefix}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "restricted_common_ports" {
  name = "${local.name_prefix}-restricted-common-ports"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "3389" # RDP
    blockedPort2 = "22"   # SSH (INCOMING_SSH_DISABLED과 중복이지만 이중 확인)
  })

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam_user_unused_credentials" {
  name = "${local.name_prefix}-iam-user-unused-credentials"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = jsonencode({
    maxCredentialUsageAge = "90"
  })

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "access_keys_rotated" {
  name = "${local.name_prefix}-access-keys-rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# IMDSv2 강제 여부를 탐지(강제 자체는 못 함 - AWS Organizations/SCP가 없으면
# "신규 인스턴스는 무조건 IMDSv2"를 계정 전체에 강제할 방법이 없음. ADR-001에서
# Organizations 도입을 프리티어 문제로 이미 기각했으므로, 탐지까지만 하고
# 위반 시 사람이/ASR이 처리하는 걸로 타협).
resource "aws_config_config_rule" "ec2_imdsv2_check" {
  name = "${local.name_prefix}-ec2-imdsv2-check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}
