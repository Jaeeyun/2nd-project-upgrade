# =============================================================================
# 보안 그룹 (Security Group)
# =============================================================================
# 트래픽 흐름: 인터넷 → ALB → EKS 노드 → RDS
# ALB 자체의 보안그룹은 AWS Load Balancer Controller가 자동으로 만들어 관리하므로
# 여기서 따로 정의하지 않습니다.
#
# 참고: security_group의 description 필드는 AWS 제약상 영문/숫자/일부 특수문자만
# 허용되고 한글(유니코드)이 들어가면 에러가 납니다. 그래서 description은 영문으로,
# 설명은 주석(한글)으로 따로 답니다.

# ---------- EKS 노드 보안그룹 (미사용) ----------
# ⚠️ 이 SG는 어떤 노드그룹/리소스에도 실제로 연결되어 있지 않다. EKS 노드는
# 이 SG 대신 EKS가 클러스터 생성 시 자동으로 만드는 클러스터 SG를 쓴다
# (32-mtls-alb.tf의 aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
# 참고 - 실제 트래픽 허용 규칙은 거기 있음). 이 리소스는 정리 대상이지만
# destroy 시 참조가 없어 안전하게 남겨둔 상태.
resource "aws_security_group" "eks_nodes_sg" {
  name        = "${local.name_prefix}-eks-nodes-sg"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.main.id
  ingress {
    description = "Allow all traffic within the VPC (node-to-node, ALB health checks)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow all outbound traffic (ECR image pull, RDS access, etc.)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-eks-nodes-sg"
  }
}

# ---------- RDS 보안그룹 ----------
resource "aws_security_group" "rds_sg" {
  name        = "${local.name_prefix}-rds-sg"
  description = "Security group for RDS PostgreSQL - VPC internal access only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow PostgreSQL (5432) from within the VPC only (includes EKS nodes)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-rds-sg"
  }
}

# ---------- 기본(default) 보안그룹 잠금 (Security Hub EC2.2 대응) ----------
# VPC 생성 시 AWS가 자동으로 만드는 default SG는 이 프로젝트 어디서도 쓰지
# 않지만(전부 목적별 SG를 따로 만들어 씀), 기본값 그대로 두면 "같은 SG를 쓰는
# 모든 대상 간 전체 트래픽 허용" 규칙이 남아있어 방치된 백도어처럼 취급됨.
# 인바운드/아웃바운드 규칙을 전부 비워서 이 SG를 실질적으로 무력화한다.
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id
  # ingress/egress 블록을 아예 안 씀 = 규칙 0개
}

resource "aws_default_security_group" "keycloak" {
  vpc_id = aws_vpc.keycloak.id
}

# 이 계정 리전의 AWS 기본 VPC(우리 프로젝트가 만든 게 아니라 계정에 원래
# 있던 것) - Terraform으로 안 만들었어도 default SG는 같은 이유로 잠근다.
data "aws_vpc" "default" {
  default = true
}

resource "aws_default_security_group" "account_default_vpc" {
  vpc_id = data.aws_vpc.default.id
}
