# =============================================================================
# K8s 네임스페이스 + RBAC (ADR-019 결정 4, 개정판) — 앱별 접근 분리는 원칙적으로
# AWS Role이 아니라 여기(K8s RBAC)서 담당한다.
# =============================================================================
# frontend/employee-backend는 dev-general(조회)/dev-lead(수정) 그룹에 열려있다.
# hr-backend는 이 둘과 똑같이 Group 기준 RoleBinding이지만, 그 Group에 매핑되는
# IAM Role만 전용(dev-hr-backend)으로 분리했다 - 최초에는 개인 사용자명 허용목록
# 방식을 검토했으나, RoleSessionName이 이론상 위조 가능해(ADR-019 "검토했던
# 대안" 참고) 위조 불가능한 Role ARN 기반 경계로 대체했다.
#
# PSS(Pod Security Standards) 강제는 ADR-009 결정 8에서 Kyverno로 하기로
# 했었지만, 실제로 쓴 기능이 baseline Audit 강제 하나뿐이었는데 그것 때문에
# 컨트롤러 파드+웹훅+Helm 배포 전체를 떠안았다. destroy 시 Kyverno의 삭제 훅
# 파드가 이미지를 못 받아와 terraform destroy가 반복적으로 멈추는 걸 실제로
# 겪은 뒤, K8s 1.25+ 내장 기능인 Pod Security Admission(PSA, 네임스페이스
# 라벨만으로 동작, 별도 컨트롤러/웹훅 없음)으로 대체했다 - ADR-009 결정 8 개정.

resource "kubernetes_namespace" "app_namespaces" {
  for_each = toset(["frontend", "employee-backend", "hr-backend"])

  metadata {
    name = each.key
    labels = {
      # PSA: baseline 기준으로 위반을 감시만 하고(Audit) 아직 막지는 않음(POL-01).
      # 충분한 관찰 후 enforce도 baseline으로 올리면 POL-02(Enforce 전환).
      "pod-security.kubernetes.io/audit"         = "baseline"
      "pod-security.kubernetes.io/audit-version" = "latest"
      "pod-security.kubernetes.io/warn"          = "baseline" # kubectl apply 시 사람에게도 바로 경고
    }
  }
}

# ---------- EKS Access Entry: IAM Role → K8s Group/개인 사용자명 ----------
# username 포맷("user:{{SessionName}}")은 AWS 요구사항("SessionName을 쓰려면
# 그 앞에 콜론이 있어야 함")을 만족시키면서, RoleSessionName(=Keycloak
# username, ADR-001)을 그대로 K8s 사용자명으로 노출한다.
#
# ⚠️ 알려진 신뢰 한계(ADR-019 "부정적/제약" 참고): RoleSessionName은
# AssumeRoleWithSAML을 직접 호출하는 경로에서 이론적으로 조작 가능해서,
# hr-backend 개인 허용목록이 이 값에 의존하는 한 완전히 위조 불가능하다고
# 단정할 수 없다. 후속 검증 필요.
resource "aws_eks_access_entry" "dev_general" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.standard["dev-general"].arn
  kubernetes_groups = ["dev-general"]
  user_name         = "user:{{SessionName}}"
  type              = "STANDARD"
}

resource "aws_eks_access_entry" "dev_lead" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.standard["dev-lead"].arn
  kubernetes_groups = ["dev-lead"]
  user_name         = "user:{{SessionName}}"
  type              = "STANDARD"
}

# ADR-019(개정): hr-backend는 개인 허용목록이 아니라 전용 Role(dev-hr-backend)의
# Group으로 처리한다 - RoleSessionName은 위조 가능하지만, 애초에 이 Role을 assume할
# 자격(Keycloak 그룹 멤버십 → SAML assertion의 Role 목록)은 위조 불가능하다.
resource "aws_eks_access_entry" "dev_hr_backend" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.standard["dev-hr-backend"].arn
  kubernetes_groups = ["dev-hr-backend"]
  user_name         = "user:{{SessionName}}"
  type              = "STANDARD"
}

resource "aws_eks_access_entry" "security_auditor" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.security_auditor.arn
  kubernetes_groups = ["security-auditor"]
  user_name         = "user:{{SessionName}}"
  type              = "STANDARD"
}

# ---------- ClusterRole: 조회 전용 / 수정 가능 두 단계 ----------
resource "kubernetes_cluster_role" "dev_view" {
  metadata {
    name = "dev-view"
  }

  rule {
    api_groups = ["", "apps", "batch"]
    resources  = ["pods", "pods/log", "deployments", "services", "configmaps", "jobs", "cronjobs", "replicasets"]
    verbs      = ["get", "list", "watch"]
  }
}

resource "kubernetes_cluster_role" "dev_edit" {
  metadata {
    name = "dev-edit"
  }

  rule {
    api_groups = ["", "apps", "batch"]
    resources  = ["pods", "pods/log", "deployments", "services", "configmaps", "jobs", "cronjobs", "replicasets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/exec"]
    verbs      = ["create"] # kubectl exec - 디버깅용
  }
}

# ---------- frontend / employee-backend: Group 기반(dev-general/dev-lead 전원) ----------
resource "kubernetes_role_binding" "dev_view_open_namespaces" {
  for_each = toset(["frontend", "employee-backend"])

  metadata {
    name      = "dev-general-view"
    namespace = kubernetes_namespace.app_namespaces[each.key].metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.dev_view.metadata[0].name
  }

  subject {
    kind      = "Group"
    name      = "dev-general"
    api_group = "rbac.authorization.k8s.io"
  }
}

resource "kubernetes_role_binding" "dev_edit_open_namespaces" {
  for_each = toset(["frontend", "employee-backend"])

  metadata {
    name      = "dev-lead-edit"
    namespace = kubernetes_namespace.app_namespaces[each.key].metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.dev_edit.metadata[0].name
  }

  subject {
    kind      = "Group"
    name      = "dev-lead"
    api_group = "rbac.authorization.k8s.io"
  }
}

# ---------- hr-backend: 전용 Role(dev-hr-backend)의 Group 기준 RoleBinding ----------
resource "kubernetes_role_binding" "hr_backend_access" {
  metadata {
    name      = "dev-hr-backend-edit"
    namespace = kubernetes_namespace.app_namespaces["hr-backend"].metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.dev_edit.metadata[0].name
  }

  subject {
    kind      = "Group"
    name      = "dev-hr-backend"
    api_group = "rbac.authorization.k8s.io"
  }
}

# ---------- security-auditor: 전체 네임스페이스 읽기전용(클러스터 단위) ----------
resource "kubernetes_cluster_role_binding" "security_auditor_view" {
  metadata {
    name = "security-auditor-view"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.dev_view.metadata[0].name
  }

  subject {
    kind      = "Group"
    name      = "security-auditor"
    api_group = "rbac.authorization.k8s.io"
  }
}

