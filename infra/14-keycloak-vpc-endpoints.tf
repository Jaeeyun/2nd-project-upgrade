# =============================================================================
# Keycloak VPC 엔드포인트 + ECR 미러 리포지토리
# =============================================================================
# Keycloak EC2가 프라이빗 서브넷(15-keycloak-vpc-peering.tf)으로 옮겨가면서
# 인터넷으로 나가는 경로(IGW/NAT)가 완전히 없어졌다. 그런데도 부트스트랩
# 스크립트(keycloak-bootstrap.sh.tpl)가 여전히 필요로 하는 것 2가지:
#   1. SSM(Session Manager 접속, 관리자 비밀번호 Parameter Store 저장)
#   2. Keycloak 컨테이너 이미지
# 1번은 AWS 서비스라 VPC 엔드포인트로 그대로 대체된다. 2번은 원래
# quay.io(외부/타사 레지스트리)에서 직접 pull했는데, 이건 AWS 서비스가
# 아니라서 VPC 엔드포인트로 대체가 안 된다 - 그래서 이 이미지를 계정 소유
# ECR로 미리 미러링해두고(scripts/mirror-keycloak-image-to-ecr.sh, 배포 전
# 사람이 인터넷 되는 자기 컴퓨터에서 1회 실행), 인스턴스는 그 ECR에서만
# 받아오게 바꿨다. 결과적으로 이 인스턴스는 배포 이후 어떤 시점에도 AWS
# 관리 네트워크 밖으로 나가는 경로가 전혀 없다(전부 PrivateLink/Gateway
# 엔드포인트로만 통신) - 그리고 외부 레지스트리에서 검증 안 된 이미지를 직접
# 받는 대신 스캔(scan_on_push)된 내부 이미지만 쓰므로 공급망 보안도 개선된다.

# ---------- ECR: Keycloak 이미지 미러 ----------
resource "aws_ecr_repository" "keycloak_mirror" {
  name                 = "${local.name_prefix}-keycloak-mirror"
  image_tag_mutability = "IMMUTABLE" # 같은 태그 재푸시로 스캔 통과한 이미지가 조용히 바뀌는 것 방지

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${local.name_prefix}-keycloak-mirror"
  }
}

resource "aws_ecr_lifecycle_policy" "keycloak_mirror" {
  repository = aws_ecr_repository.keycloak_mirror.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "최신 5개만 유지"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

# Keycloak EC2 Role만 pull 가능 - push는 사람이 scripts/mirror-keycloak-image-to-ecr.sh로
# 자기 자격증명으로 직접 함(별도 CI/CD 파이프라인 없음, PoC 규모상 과함).
data "aws_iam_policy_document" "keycloak_ecr_pull" {
  statement {
    effect    = "Allow"
    actions   = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability"]
    resources = [aws_ecr_repository.keycloak_mirror.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # GetAuthorizationToken은 리소스 레벨 제한을 지원하지 않는 액션
  }
}

resource "aws_iam_role_policy" "keycloak_ecr_pull" {
  name   = "keycloak-ecr-pull"
  role   = aws_iam_role.keycloak_ec2.id
  policy = data.aws_iam_policy_document.keycloak_ecr_pull.json
}

output "keycloak_ecr_repository_url" {
  description = "scripts/mirror-keycloak-image-to-ecr.sh로 이미지를 여기에 먼저 올려야 Keycloak EC2가 부팅됨"
  value       = aws_ecr_repository.keycloak_mirror.repository_url
}

# ---------- VPC 엔드포인트용 보안그룹 ----------
resource "aws_security_group" "keycloak_vpc_endpoints" {
  name        = "${local.name_prefix}-keycloak-vpce-sg"
  description = "Keycloak VPC 엔드포인트 - 프라이빗 서브넷에서만 443 인바운드"
  vpc_id      = aws_vpc.keycloak.id
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_vpce_from_private" {
  security_group_id = aws_security_group.keycloak_vpc_endpoints.id
  cidr_ipv4          = var.keycloak_vpc_private_subnet_cidr
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "keycloak_vpce_out" {
  security_group_id = aws_security_group.keycloak_vpc_endpoints.id
  cidr_ipv4          = "0.0.0.0/0"
  ip_protocol        = "-1"
}

# ---------- Interface 엔드포인트 (ECR API/DKR, SSM 3종) ----------
locals {
  keycloak_interface_endpoints = toset([
    "ecr.api", "ecr.dkr", "ssm", "ssmmessages", "ec2messages",
  ])
}

resource "aws_vpc_endpoint" "keycloak_interface" {
  for_each            = local.keycloak_interface_endpoints
  vpc_id              = aws_vpc.keycloak.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type    = "Interface"
  subnet_ids           = [aws_subnet.keycloak_private.id]
  security_group_ids   = [aws_security_group.keycloak_vpc_endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${local.name_prefix}-keycloak-vpce-${each.value}"
  }
}

# ---------- Gateway 엔드포인트 (S3 - ECR 이미지 레이어의 실제 저장소) ----------
# ECR API/DKR는 위 Interface 엔드포인트로 처리되지만, 실제 이미지 레이어(blob)는
# S3에서 내려받는다 - 이것까지 막히면 docker pull이 매니페스트만 받고 레이어에서
# 멈춘다. Gateway 타입이라 라우트 테이블에 직접 연결(과금 없음).
resource "aws_vpc_endpoint" "keycloak_s3" {
  vpc_id            = aws_vpc.keycloak.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.keycloak_private.id]
}
