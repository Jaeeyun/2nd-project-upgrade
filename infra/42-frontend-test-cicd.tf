# =============================================================================
# frontend-test Keyless CI/CD 증적용 인프라 (Scene 12) — 22-cicd-oidc.tf가
# 만든 github_ci Role이 실제로 ECR push + EKS 배포까지 할 수 있게 권한/
# 네임스페이스를 붙인다.
# =============================================================================
# hr-app/frontend(실서비스용, frontend 네임스페이스)와는 완전히 분리된 별도
# 앱/네임스페이스/ECR 리포지토리다 - CI/CD 파이프라인 자체를 증명하는 용도라
# 실서비스에 영향 없이 반복 배포해도 안전하게 격리한다.
#
# 태그는 :latest 재사용이 아니라 git SHA 기준으로 매번 새 태그를 push한다 -
# 07-ecr.tf의 frontend/backend 리포지토리가 ECR.2(태그 불변성)를 못 켠 이유가
# 바로 :latest 재사용 때문이었는데(Track 4), 이 리포지토리는 처음부터 SHA
# 태그로 만들어서 IMMUTABLE로 켤 수 있다.

resource "aws_ecr_repository" "frontend_test" {
  name                 = "${local.name_prefix}-frontend-test-repo"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "frontend_test" {
  repository = aws_ecr_repository.frontend_test.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "최근 10개 이미지만 유지"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

# ---------- github_ci Role에 ECR push 권한 추가 (22-cicd-oidc.tf의 베이스라인엔 없었음) ----------
data "aws_iam_policy_document" "github_ci_ecr_frontend_test" {
  statement {
    sid       = "EcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # 이 액션은 리소스 레벨 제한을 지원하지 않음(AWS 사양)
  }

  statement {
    sid    = "EcrPushFrontendTestOnly"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:PutImage",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
    ]
    resources = [aws_ecr_repository.frontend_test.arn]
  }
}

resource "aws_iam_role_policy" "github_ci_ecr_frontend_test" {
  name   = "github-ci-ecr-frontend-test"
  role   = aws_iam_role.github_ci.id
  policy = data.aws_iam_policy_document.github_ci_ecr_frontend_test.json
}

# ---------- K8s 네임스페이스 (실서비스 frontend와 격리) ----------
resource "kubernetes_namespace" "frontend_test" {
  metadata {
    name = "frontend-test"
    labels = {
      "pod-security.kubernetes.io/audit"         = "baseline"
      "pod-security.kubernetes.io/audit-version" = "latest"
      "pod-security.kubernetes.io/warn"          = "baseline"
    }
  }
}

# ---------- EKS Access Entry: github_ci Role → K8s Group "ci-frontend-test" ----------
# 34-k8s-namespaces-rbac.tf의 dev-general/dev-lead와 같은 패턴(Group 기준
# RoleBinding). SessionName이 아니라 Role ARN 자체를 principal로 매핑하므로
# 위조 문제(ADR-019)와 무관하다 - OIDC 신뢰 정책 자체가 이미 저장소/브랜치를
# 제한하고 있음(22-cicd-oidc.tf).
resource "aws_eks_access_entry" "github_ci" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.github_ci.arn
  kubernetes_groups = ["ci-frontend-test"]
  type              = "STANDARD"
}

# dev-edit ClusterRole(34-k8s-namespaces-rbac.tf)을 frontend-test 네임스페이스에만
# 한정해서 재사용 - 새 ClusterRole을 또 만들 필요 없음.
resource "kubernetes_role_binding" "ci_frontend_test_edit" {
  metadata {
    name      = "ci-frontend-test-edit"
    namespace = kubernetes_namespace.frontend_test.metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.dev_edit.metadata[0].name
  }

  subject {
    kind      = "Group"
    name      = "ci-frontend-test"
    api_group = "rbac.authorization.k8s.io"
  }
}

# ---------- Keycloak EC2 → 같은 그룹 (SSM RunCommand 실행 경로용) ----------
# GitHub Actions 러너는 EKS 퍼블릭 엔드포인트에 직접 못 붙는다(엔드포인트가
# keycloak_admin_cidr류의 관리자 IP로만 제한돼 있고, 러너 IP는 매번 바뀌는
# GitHub 소유 대역이라 허용목록에 넣을 수 없음/넣으면 안 됨). 대신 워크플로가
# VPC 안에 이미 있는 Keycloak EC2에 SSM RunCommand로 kubectl을 대신
# 실행시킨다(22-cicd-oidc.tf의 github_ci 베이스라인 권한에 ssm:SendCommand/
# GetCommandInvocation이 이미 포함돼 있던 이유) - 이러면 이 kubectl 실행이
# Keycloak EC2의 IAM Role로 인증되므로, 그 Role도 같은 K8s Group에 넣어야 한다.
#
# [2026-08 재설계] 이 kubectl 실행 자체(Keycloak EC2 → EKS API)는 원래
# eks_public_access_cidrs에 Keycloak 퍼블릭 IP를 허용목록으로 넣어 퍼블릭
# 엔드포인트로 나갔었다. Keycloak이 프라이빗 서브넷으로 옮겨가면서 그 경로가
# 아예 사라졌는데, 15-keycloak-vpc-peering.tf에서 Peering의
# allow_remote_vpc_dns_resolution을 켠 덕분에 이제 EKS 프라이빗 엔드포인트
# (04-eks.tf, endpoint_private_access=true)로 Peering 사설 경로를 통해
# 바로 닿는다 - 오히려 퍼블릭 엔드포인트를 안 거치게 돼서 더 안전해졌다.
resource "aws_eks_access_entry" "keycloak_ec2" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.keycloak_ec2.arn
  kubernetes_groups = ["ci-frontend-test"]
  type              = "STANDARD"
}

# Access Entry만으로는 K8s RBAC만 붙을 뿐, kubectl이 `aws eks
# update-kubeconfig`/토큰 발급 단계에서 필요로 하는 IAM 쪽
# eks:DescribeCluster 자체는 별도로 허용돼야 한다 - Keycloak EC2 Role
# 원래 정의(11-keycloak.tf)엔 EKS 권한이 전혀 없었음.
data "aws_iam_policy_document" "keycloak_ec2_eks_describe" {
  statement {
    effect    = "Allow"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.main.arn]
  }
}

resource "aws_iam_role_policy" "keycloak_ec2_eks_describe" {
  name   = "keycloak-ec2-eks-describe-frontend-test-cicd"
  role   = aws_iam_role.keycloak_ec2.id
  policy = data.aws_iam_policy_document.keycloak_ec2_eks_describe.json
}

output "frontend_test_ecr_repository_url" {
  value = aws_ecr_repository.frontend_test.repository_url
}
