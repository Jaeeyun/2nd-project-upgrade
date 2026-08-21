# =============================================================================
# ASR 실제 remediation 런북 배포 (ADR-014 보완) — admin 스택만으로는 동작 안 함
# =============================================================================
# 27-asr-remediation.tf가 배포하는 admin 템플릿은 오케스트레이터(Step
# Functions)일 뿐, 실제로 finding을 고치는 런북(SSM Automation 문서)은
# member-roles/member 템플릿에 들어있다. AWS Organizations 없이 단일 계정만
# 쓰더라도 이 계정 자신이 "member 계정 1개"로 취급되어 두 템플릿을 이
# 계정에 똑같이 배포해야 한다(27-asr-remediation.tf의 기존 주석은 이 부분을
# Service Catalog로 잘못 설명하고 있었음 - 실제로는 별도 CloudFormation
# 스택 2개).
#
# admin 스택이 LoadSCAdminStack=yes(LoadAFSBPAdminStack=no)로 떠 있으므로,
# member 쪽도 LoadSCMemberStack=yes로 맞춘다 - "SC"(Security Control)는
# Security Hub의 통합 control ID(예: EC2.13) 기준 런북 묶음으로, 예전
# AFSBP 전용 이름을 대체한 것. 두 스택의 로드 옵션이 어긋나면 orchestrator가
# 해당 control의 런북을 못 찾는다.

locals {
  # Namespace 파라미터는 S3 버킷 네이밍 규칙을 따라야 하고 3~9자로 제한된다
  # (AWS 검증 메시지 기준) - local.name_prefix("demo-project-dev")는 너무 길어
  # 못 쓴다. member-roles/member 두 스택 사이에서만 일치하면 되고, admin
  # 스택과는 무관하다.
  asr_namespace = "asrdemo"
}

resource "aws_cloudformation_stack" "asr_member_roles" {
  count        = var.enable_asr_remediation ? 1 : 0
  name         = "${local.name_prefix}-asr-member-roles"
  template_url = "https://s3.amazonaws.com/solutions-reference/automated-security-response-on-aws/latest/automated-security-response-member-roles.template"
  capabilities = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"]

  parameters = {
    SecHubAdminAccount = data.aws_caller_identity.current.account_id
    Namespace          = local.asr_namespace
  }

  tags = {
    Name = "${local.name_prefix}-asr-member-roles"
  }
}

resource "aws_cloudformation_stack" "asr_member" {
  count        = var.enable_asr_remediation ? 1 : 0
  name         = "${local.name_prefix}-asr-member"
  template_url = "https://s3.amazonaws.com/solutions-reference/automated-security-response-on-aws/latest/automated-security-response-member.template"
  capabilities = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]

  parameters = {
    SecHubAdminAccount                    = data.aws_caller_identity.current.account_id
    Namespace                             = local.asr_namespace
    LogGroupName                          = aws_cloudwatch_log_group.cloudtrail.name
    EnableCloudTrailForASRActionLog       = "no"  # 이미 08-cloudtrail.tf의 CloudTrail 파이프라인이 있어 중복 불필요
    CreateS3BucketForRedshiftAuditLogging = "no"  # Redshift 미사용
    LoadSCMemberStack                     = "yes" # admin의 LoadSCAdminStack=yes와 맞춤 - EC2.13 포함
    LoadAFSBPMemberStack                  = "no"
    LoadCIS120MemberStack                 = "no"
    LoadCIS140MemberStack                 = "no"
    LoadCIS300MemberStack                 = "no"
    LoadNIST80053MemberStack              = "no"
    LoadPCI321MemberStack                 = "no"
  }

  tags = {
    Name = "${local.name_prefix}-asr-member"
  }

  depends_on = [aws_cloudformation_stack.asr_member_roles]
}

output "asr_member_stack_id" {
  value = var.enable_asr_remediation ? aws_cloudformation_stack.asr_member[0].id : "disabled (enable_asr_remediation=false)"
}
