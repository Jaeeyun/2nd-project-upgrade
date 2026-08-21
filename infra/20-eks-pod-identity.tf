# =============================================================================
# EKS Pod Identity 애드온 (ADR-009 결정 1)
# =============================================================================
# 애드온 자체를 켜두면, 이후 앱을 배포할 때 aws_eks_pod_identity_association으로
# ServiceAccount별 Role 연결만 추가하면 된다(전용 최소권한 Role - ADR-009 결정
# 3). 지금 이 저장소엔 배포된 애플리케이션이 없어서 연결 예시는 만들지 않고,
# 애드온 활성화까지만 해둔다.

resource "aws_eks_addon" "pod_identity" {
  cluster_name  = aws_eks_cluster.main.name
  addon_name    = "eks-pod-identity-agent"
  addon_version = null # 최신 호환 버전 자동 선택

  depends_on = [aws_eks_node_group.app]
}

# ---------- 예시(주석 처리) - 실제 앱 배포 시 이렇게 연결 ----------
# resource "aws_iam_role" "app_example" {
#   name = "${local.name_prefix}-app-example-role"
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [{
#       Effect    = "Allow"
#       Action    = ["sts:AssumeRole", "sts:TagSession"]
#       Principal = { Service = "pods.eks.amazonaws.com" }
#     }]
#   })
# }
#
# resource "aws_eks_pod_identity_association" "app_example" {
#   cluster_name    = aws_eks_cluster.main.name
#   namespace       = "platform"
#   service_account = "app-example-sa"
#   role_arn        = aws_iam_role.app_example.arn
# }
