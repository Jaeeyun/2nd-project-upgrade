# =============================================================================
# Misconfiguration 자동조치 (ADR-014, 수정본) — ASR을 Terraform으로 감싸서 배포
# =============================================================================
# AWS Solutions "Automated Security Response on AWS"의 admin 템플릿을
# aws_cloudformation_stack으로 감싼다. 이 계정은 AWS Organizations를 안 쓰므로
# (ADR-001에서 프리티어 문제로 기각) member-roles/member 템플릿은 불필요하고,
# admin 템플릿 하나만 이 계정에 단독으로 배포하면 된다.
#
# 이 파일은 오케스트레이터(관리 뼈대)만 배포한다. 실제로 finding을 고쳐주는
# 런북(SSM Automation 문서)은 Service Catalog가 아니라 별도 CloudFormation
# 템플릿 2개(member-roles, member)에 들어있다 - 41-asr-member-remediation.tf
# 참고. 그 파일이 함께 배포되어야 Security Hub Custom Action("ASRRemediation")을
# 눌렀을 때 실제로 finding이 고쳐진다.
#
# 배포 시 알아둘 것: Web UI(CloudFront+Cognito)는 이 프로젝트가 안 쓰므로
# `parameters.ShouldDeployWebUI = "no"`로 꺼둔다 - 켜두면 Web UI용 Lambda들이
# 계정 기본 Lambda 동시실행 할당량을 초과 요구해서 스택 배포가 실패할 수 있다
# (자세한 원인은 TROUBLESHOOTING.md 참고).

variable "enable_asr_remediation" {
  description = "Automated Security Response on AWS(27-asr-remediation.tf) 활성화 여부. 이 템플릿의 Web UI 구성요소가 계정의 Lambda 동시실행 할당량을 초과 요구할 수 있어(신규/제한된 계정에서 흔함), 할당량 증가가 확인되기 전까지는 false로 두고 나머지 인프라부터 배포하는 용도."
  type        = bool
  default     = false
}

resource "aws_cloudformation_stack" "asr" {
  count        = var.enable_asr_remediation ? 1 : 0
  name         = "${local.name_prefix}-asr"
  template_url = var.asr_template_url
  capabilities = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]

  parameters = {
    ShouldDeployWebUI = "no"
  }

  tags = {
    Name = "${local.name_prefix}-asr"
  }
}

# Security Hub CloudFormation.1(종료 보호) 대응 - aws_cloudformation_stack
# 리소스 자체엔 enable_termination_protection 인자가 없어서(terraform validate로
# 확인) null_resource + local-exec로 우회. destroy 시에는 반대로 보호를 먼저
# 풀어야 terraform destroy가 스택을 지울 수 있으므로, destroy-time
# provisioner로 반드시 같이 해제한다(안 하면 destroy가 CloudFormation
# DELETE_FAILED로 막힘).
resource "null_resource" "asr_termination_protection" {
  count = var.enable_asr_remediation ? 1 : 0

  triggers = {
    stack_name = aws_cloudformation_stack.asr[0].name
    region     = var.aws_region
  }

  provisioner "local-exec" {
    command = "aws cloudformation update-termination-protection --enable-termination-protection --stack-name ${self.triggers.stack_name} --region ${self.triggers.region}"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name ${self.triggers.stack_name} --region ${self.triggers.region} || true"
  }
}

variable "asr_template_url" {
  description = "Automated Security Response on AWS admin 템플릿의 S3 URL"
  type        = string
  default     = "https://s3.amazonaws.com/solutions-reference/automated-security-response-on-aws/latest/automated-security-response-admin.template"
}

# ASR이 SNS 알림을 자체적으로 생성하지만, 우리 기존 파이프라인(23-security-alerting.tf)
# 으로도 흘러가게 하려면 ASR 배포 완료 후 콘솔에서 ASR의 SNS 토픽에
# aws_sns_topic.security_alerts를 구독시키는 별도 작업이 필요합니다(ASR 스택이
# 만드는 리소스 이름은 apply 후 출력값으로 확인).

output "asr_stack_id" {
  value = var.enable_asr_remediation ? aws_cloudformation_stack.asr[0].id : "disabled (enable_asr_remediation=false)"
}
