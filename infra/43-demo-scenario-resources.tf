# =============================================================================
# 데모 시나리오 전용 리소스 (Scene 5, 8) — 실제 서비스와 무관한 격리된 대상
# =============================================================================
# Scene 8(ASR 오설정 탐지→Slack 1-Click 승인→원복)을 촬영하려면 SSH
# 0.0.0.0/0 같은 오설정을 실제로 한 번 만들었다가 자동조치로 원복되는 걸
# 보여줘야 한다. Keycloak/Pomerium/EKS 노드처럼 실제로 트래픽을 받는
# 보안그룹에 이 실험을 하면 촬영 NG로 여러 번 반복할 때마다 실제 서비스가
# 잠깐씩 진짜로 노출된다 - 그래서 아무 인스턴스에도 붙지 않는 이 전용
# 더미 보안그룹에서만 오설정을 만들었다 지웠다 한다.
#
# 기본 상태(이 파일 그대로 apply한 상태)는 SSH 룰이 없는 정상 상태다 -
# scripts/scenarios/08-asr-remediation.sh가 실행 중에만 0.0.0.0/0:22 룰을
# 추가했다가, ASR 자동조치(또는 스크립트 자체의 안전장치)로 다시 제거한다.
resource "aws_security_group" "asr_demo_target" {
  name        = "${local.name_prefix}-asr-demo-target-sg"
  description = "Scene 8 ASR remediation demo target - not attached to any instance"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name    = "${local.name_prefix}-asr-demo-target-sg"
    Purpose = "asr-demo-scene8"
  }
}

output "asr_demo_target_sg_id" {
  value = aws_security_group.asr_demo_target.id
}

# ---------- Scene 5: RDS IAM DB Auth 검증용 권한 ----------
# rds_sg(03-security.tf)는 demo VPC CIDR만 허용해서 Keycloak(다른 VPC)에서는
# 애초에 5432에 못 붙는다(실측으로 확인 - Connection timed out) - EKS 워커
# 노드는 같은 VPC라 접속 가능하므로, scripts/scenarios/05-rds-pii-masking.sh는
# kubectl run으로 뜨는 임시 디버그 파드에서 psql을 실행한다.
#
# 실제 SAML Role(dev-general 등)을 스크립트에서 assume하려면 진짜 브라우저
# SAML 로그인이 필요해 자동화가 안 되므로, 이 검증 목적에 한해 EKS 노드
# Role에 general_user_readonly/security_auditor_readonly 두 DB 사용자로
# connect할 권한만 좁게 부여한다 - 실제 SAML Role들의 권한 경계 자체를
# 바꾸는 게 아니다.
# ⚠️ 트레이드오프: Pod Identity로 이 파드 하나에만 권한을 주는 게 더
# 정교하지만(ADR-011), 이 저장소엔 아직 Pod Identity 연결 사례가 하나도
# 없어(ADR-009) 그 골격부터 새로 만들어야 한다. 검증용 임시 파드 하나가
# 목적이라 노드 Role에 좁게 추가하는 실용적 선택을 했다 - 두 DB 사용자
# 모두 마스킹된 읽기 전용 뷰만 보므로 노드의 다른 파드가 같이 이 권한을
# 상속해도 실질 노출은 제한적이다.
# db_admin은 Scene 9(scripts/scenarios/09-permission-drift.sh)가 검증용
# 권한 드리프트(원본 테이블 직접 GRANT)를 일부러 만들었다가 Lambda가
# 되돌리는지 확인하는 데 쓴다 - db_admin 자체가 테이블 소유자급 권한이라
# 이 데모 목적 밖에서는 노출 범위가 더 크므로, 실제 운영 전환 시 가장
# 먼저 Pod Identity로 좁혀야 할 항목이다.
data "aws_iam_policy_document" "eks_node_rds_connect_demo" {
  statement {
    effect  = "Allow"
    actions = ["rds-db:connect"]
    resources = [
      "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/general_user_readonly",
      "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/security_auditor_readonly",
      "arn:aws:rds-db:${var.aws_region}:${data.aws_caller_identity.current.account_id}:dbuser:${aws_db_instance.main.resource_id}/db_admin",
    ]
  }
}

resource "aws_iam_role_policy" "eks_node_rds_connect_demo" {
  name   = "eks-node-rds-connect-scene5-demo"
  role   = aws_iam_role.eks_node_role.id
  policy = data.aws_iam_policy_document.eks_node_rds_connect_demo.json
}
