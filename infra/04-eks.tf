# =============================================================================
# EKS 클러스터
# =============================================================================
# 노드그룹은 단일 구성이다. 워크로드별로 노드를 분리하려면(예: 특정 파드만
# 특정 노드에 배치) taint/toleration을 추가하고 노드그룹을 나눠야 한다 -
# taint 없이 노드그룹만 나누면 스케줄러가 아무 노드에나 배치해 분리 효과가 없다.

# ---------- EKS 클러스터용 IAM Role ----------
resource "aws_iam_role" "eks_cluster_role" {
  name = "${local.name_prefix}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "eks.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# ---------- EKS 노드용 IAM Role ----------
resource "aws_iam_role" "eks_node_role" {
  name = "${local.name_prefix}-eks-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "ecr_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cloudwatch_agent" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.eks_node_role.name
}

# EKS 워커 노드는 원래 SSM 없이 뒀었지만(쿠버네티스 운영에서는 노드 셸에 직접
# 들어갈 일이 드물어서), 노드 자체 장애(디스크 꽉 참, kubelet 다운 등) 대응용
# 비상 접속 경로로 추가함. ADR-002 원칙(SSM만 사용, SSH 없음)을 EKS 노드에도
# 동일하게 적용.
resource "aws_iam_role_policy_attachment" "eks_node_ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.eks_node_role.name
}

# ---------- 컨트롤플레인 로그 그룹 (비용 최적화) ----------
# EKS가 로그 그룹을 자동으로 만들면 보존기간이 "무기한"이라 스토리지 비용이
# 계속 쌓입니다. Terraform이 먼저 만들어서 보존기간/로그클래스를 직접 관리합니다.
# log_group_class = INFREQUENT_ACCESS: 실시간 알림 없이 사후 조회(누가 언제 어떤
# kubectl 명령을 쳤는지 찾아보는 용도)만 할 거라면 Standard 대비 인제스트 비용 절반.
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/${local.name_prefix}-cluster/cluster"
  retention_in_days = 90
  log_group_class   = "INFREQUENT_ACCESS"
}

# ---------- EKS 클러스터 ----------
resource "aws_eks_cluster" "main" {
  name     = "${local.name_prefix}-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.eks_cluster_version

  vpc_config {
    subnet_ids              = concat(aws_subnet.private_app[*].id, aws_subnet.public[*].id)
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.eks_public_access_cidrs
  }

  # EKS Access Entry(IAM Role ↔ K8s RBAC 매핑)를 쓰려면 이 블록이 필수. 레거시
  # aws-auth ConfigMap 방식은 안 쓰므로 "API" 단일 모드로 설정(ADR-019).
  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  # audit만 켠다: "누가 어느 IP에서 어떤 kubectl 명령을 쳤는지"에 필요한 건
  # audit 로그 하나뿐. api/authenticator/controllerManager/scheduler는 컨트롤
  # 플레인 내부 동작 로그라 이 목적엔 안 쓰이면서 볼륨만 키운다.
  enabled_cluster_log_types = ["audit"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_cloudwatch_log_group.eks_cluster, # 로그 그룹이 먼저 있어야 EKS가 이걸 재사용함
  ]
}

# Security Hub EC2.8(IMDSv2 강제) 대응 - aws_eks_node_group 자체에는 metadata
# 옵션이 없어서 커스텀 launch template으로 우회. instance_types/ami_type은
# 노드그룹 쪽 설정을 그대로 쓰도록 여기서는 지정하지 않음(둘 다 지정하면 충돌).
resource "aws_launch_template" "eks_node" {
  name_prefix = "${local.name_prefix}-eks-node-"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 강제
    http_put_response_hop_limit = 2          # 기본값 1이면 파드(컨테이너) 안에서 노드 메타데이터에 한 홉 더 거쳐 접근 못 함(EKS 흔한 함정)
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${local.name_prefix}-eks-node"
    }
  }
}

# ---------- EKS 노드그룹 (단일) ----------
resource "aws_eks_node_group" "app" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${local.name_prefix}-app-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = aws_subnet.private_app[*].id

  scaling_config {
    desired_size = var.eks_node_desired_size
    min_size     = var.eks_node_min_size
    max_size     = var.eks_node_max_size
  }

  instance_types = [var.eks_node_instance_type]
  ami_type       = "AL2_x86_64"

  launch_template {
    id      = aws_launch_template.eks_node.id
    version = aws_launch_template.eks_node.latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.ecr_read_only,
    aws_iam_role_policy_attachment.eks_cloudwatch_agent,
  ]
}

# ⚠️ enableNetworkPolicy=true가 반드시 켜져 있어야 한다. 이게 꺼지면
# 31-hr-app-network-policy.tf(HR 격리)와 29-eks-pod-isolation.tf(파드 격리
# 대응)의 NetworkPolicy 오브젝트가 K8s API에는 정상 생성되지만 데이터플레인
# (aws-eks-nodeagent)에서는 전혀 강제되지 않는다 - 조용히 실패하는 방식이라
# 발견하기 어려우니 이 값을 건드릴 때 주의할 것.
resource "aws_eks_addon" "vpc_cni" {
  cluster_name  = aws_eks_cluster.main.name
  addon_name    = "vpc-cni"
  addon_version = null # 최신 호환 버전 자동 선택

  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
  })

  depends_on = [aws_eks_node_group.app]
}
