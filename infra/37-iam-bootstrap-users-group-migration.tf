# =============================================================================
# 부트스트랩/비상용 IAM 사용자 - Group 기반 권한으로 재구성 (Security Hub IAM.2 대응)
# =============================================================================
# terraform-admin/dev-admin은 SAML 연동이 서기 전 부트스트랩용, 그리고 비상시
# break-glass 접근용으로 이 Terraform 밖(콘솔/CLI)에서 미리 만들어진 사용자다.
# 이 프로젝트의 설계 철학(ADR-001: 사람의 AWS 접근은 SAML 임시자격증명만 사용)과
# 어긋나지만, "SAML/Keycloak 자체가 고장났을 때 들어갈 방법이 아예 없어지는"
# 상황을 막기 위해 삭제하지 않고 유지하기로 함(2026-08-13 결정).
#
# 대신 Security Hub IAM.2("IAM 사용자에 정책을 직접 붙이지 말 것")를 충족하도록
# 정책을 Group으로 옮긴다 - 사용자 자체는 이 Terraform이 만들지 않았으므로
# import하지 않고, Group + 멤버십만 관리한다(사용자 이름은 문자열로만 참조).
#
# ⚠️ 적용 순서 중요(직접 겪은 문제 아님, 사전에 설계한 순서): terraform apply로
# 먼저 Group을 만들고 멤버십을 추가한 다음에만, 아래 outputs가 알려주는 CLI로
# 기존 직접 첨부 정책을 수동으로 detach해야 한다. 순서를 바꿔서 직접 정책부터
# 떼면 Group 권한이 아직 없는 상태로 접근이 끊길 수 있다(특히 dev-admin은 이
# Terraform을 실행하는 세션 본인의 자격증명이라 더 위험함 - detach 후 반드시
# 즉시 aws sts get-caller-identity 등으로 접근이 살아있는지 확인할 것).

resource "aws_iam_group" "bootstrap_admins" {
  name = "${local.name_prefix}-bootstrap-admins"
}

resource "aws_iam_group_policy_attachment" "bootstrap_admins" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess",
    "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess",
  ])
  group      = aws_iam_group.bootstrap_admins.name
  policy_arn = each.value
}

resource "aws_iam_user_group_membership" "terraform_admin" {
  user = "terraform-admin"
  groups = [aws_iam_group.bootstrap_admins.name]
}

resource "aws_iam_group" "emergency_admins" {
  name = "${local.name_prefix}-emergency-admins"
}

resource "aws_iam_group_policy_attachment" "emergency_admins" {
  group      = aws_iam_group.emergency_admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user_group_membership" "dev_admin" {
  user = "dev-admin"
  groups = [aws_iam_group.emergency_admins.name]
}

# 아래 CLI 명령은 위 apply가 성공한 뒤에만 실행할 것(직접 첨부된 기존 정책 제거).
# Terraform이 이 두 사용자를 관리하지 않아서(import 안 함) 자동화하지 않고
# 의도적으로 사람이 확인하며 실행하게 output으로만 안내한다.
output "iam2_manual_cleanup_commands" {
  description = "Group 멤버십 적용 확인 후, 이 명령으로 기존 직접 첨부 정책을 제거하세요(순서 중요)"
  value = [
    "aws iam detach-user-policy --user-name terraform-admin --policy-arn arn:aws:iam::aws:policy/AmazonSSMFullAccess",
    "aws iam detach-user-policy --user-name terraform-admin --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "aws iam detach-user-policy --user-name terraform-admin --policy-arn arn:aws:iam::aws:policy/IAMFullAccess",
    "aws iam detach-user-policy --user-name terraform-admin --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess",
    "aws iam detach-user-policy --user-name terraform-admin --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_FullAccess",
    "aws iam detach-user-policy --user-name terraform-admin --policy-arn arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess",
    "aws iam detach-user-policy --user-name dev-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
  ]
}
