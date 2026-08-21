# =============================================================================
# Keycloak VPC + VPC Peering (demo VPC와 분리, 사설 라우팅으로만 연결)
# =============================================================================
# 지금 이 두 VPC는 "나중에 실제 Site-to-Site VPN으로 연결될 온프레미스/사내망"과
# "AWS demo VPC"의 관계를 미리 흉내낸 것이다. Peering은 VPN Gateway처럼 시간당
# 과금되는 리소스가 없고(연결 자체 무료), 같은 AZ 안에서 오가는 트래픽은
# 데이터전송료도 무료라서, 실제 VPN 어플라이언스를 띄우지 않고도 "사설 IP로만
# 서로 도달 가능한 두 네트워크"라는 핵심 특성을 값싸게 재현할 수 있다.
#
# [2026-08 재설계] 원래는 "퍼블릭 서브넷 + SG만 잠금" 방식이었다 - PoC 목적상
# 진짜 private subnet(+NAT Gateway, 월 4~5만원 상시 과금)까지는 필요 없다고
# 판단했었다. 그런데 SG 하나로만 막는 방식은 결국 "사람이 실수로 0.0.0.0/0을
# 안 열길" 바라는 것에 의존하는 구조라(실제로 2026-08-12에 테스트 편의상
# 전체 오픈했다가 다시 축소한 이력이 있음), IdP처럼 뚫리면 SSO 전체가
# 위험해지는 고가치 타겟에는 약한 방어선이라고 재판단했다.
#
# "private subnet은 NAT Gateway가 필수"라는 원래 전제도 틀렸다 - NAT는
# 아웃바운드(인스턴스가 인터넷으로 나가는 것)에만 필요하고, 인바운드(로그인
# 화면을 브라우저가 접속하는 것)는 퍼블릭 ALB를 앞에 세우면 NAT 없이
# 해결된다. 남은 유일한 아웃바운드 필요성은 keycloak-bootstrap.sh.tpl의
# `docker pull quay.io/keycloak/keycloak`인데, 이건 이미지를 ECR로 미리
# 미러링해두면(scripts/mirror-keycloak-image-to-ecr.sh, 배포 전 1회 수동 실행)
# VPC 엔드포인트(18-keycloak-vpc-endpoints.tf)만으로 완전히 대체된다.
# 외부 레지스트리에서 직접 pull하지 않고 스캔된 내부 ECR 이미지만 쓴다는
# 점에서 공급망 보안 관점에서도 원래 방식보다 낫다.
#
# 최종 구조: 퍼블릭 서브넷엔 ALB만(EC2 없음), Keycloak EC2는 프라이빗
# 서브넷으로 이동. EKS 컨트롤플레인은 이미 endpoint_private_access=true라서
# (04-eks.tf), 이 VPC에서 Peering 사설 경로로 EKS API에 직접 도달 가능하다
# (42-frontend-test-cicd.tf의 SSM RunCommand-kubectl 플로우가 이 경로를 씀) -
# 단, Peering만으로는 프라이빗 EKS 엔드포인트의 DNS 이름이 안 풀려서
# allow_remote_vpc_dns_resolution을 아래 Peering 리소스에 추가로 켰다.

# ---------- Keycloak VPC ----------
resource "aws_vpc" "keycloak" {
  cidr_block           = var.keycloak_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-keycloak-vpc"
  }
}

resource "aws_internet_gateway" "keycloak" {
  vpc_id = aws_vpc.keycloak.id

  tags = {
    Name = "${local.name_prefix}-keycloak-igw"
  }
}

# demo VPC의 첫 번째 퍼블릭 서브넷과 같은 AZ에 둔다 - 같은 AZ 안에서 오가는
# Peering 트래픽은 데이터전송료가 무료이기 때문(다른 AZ면 방향당 $0.01/GB).
resource "aws_subnet" "keycloak_public" {
  vpc_id                  = aws_vpc.keycloak.id
  cidr_block              = var.keycloak_vpc_public_subnet_cidr
  availability_zone       = local.azs[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${local.name_prefix}-keycloak-public-subnet"
  }
}

resource "aws_route_table" "keycloak_public" {
  vpc_id = aws_vpc.keycloak.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.keycloak.id
  }

  route {
    cidr_block                = var.vpc_cidr # demo VPC 전체로 사설 라우팅
    vpc_peering_connection_id = aws_vpc_peering_connection.keycloak_to_demo.id
  }

  tags = {
    Name = "${local.name_prefix}-keycloak-public-rt"
  }
}

resource "aws_route_table_association" "keycloak_public" {
  subnet_id      = aws_subnet.keycloak_public.id
  route_table_id = aws_route_table.keycloak_public.id
}

# ---------- Keycloak 프라이빗 서브넷 (EC2 실제 배치 위치) ----------
resource "aws_subnet" "keycloak_private" {
  vpc_id            = aws_vpc.keycloak.id
  cidr_block        = var.keycloak_vpc_private_subnet_cidr
  availability_zone = local.azs[0] # 퍼블릭 서브넷과 같은 AZ(ALB-EC2 간 트래픽도 AZ 간 전송료 없게)

  tags = {
    Name = "${local.name_prefix}-keycloak-private-subnet"
  }
}

# IGW로 가는 라우트가 없다 - 이 서브넷엔 인터넷으로 나가는 경로 자체가 없고,
# ECR/SSM 등은 전부 VPC 엔드포인트(18-keycloak-vpc-endpoints.tf)로, demo VPC
# 자원은 아래 Peering 라우트로만 도달 가능하다.
resource "aws_route_table" "keycloak_private" {
  vpc_id = aws_vpc.keycloak.id

  route {
    cidr_block                = var.vpc_cidr
    vpc_peering_connection_id = aws_vpc_peering_connection.keycloak_to_demo.id
  }

  tags = {
    Name = "${local.name_prefix}-keycloak-private-rt"
  }
}

resource "aws_route_table_association" "keycloak_private" {
  subnet_id      = aws_subnet.keycloak_private.id
  route_table_id = aws_route_table.keycloak_private.id
}

# ---------- VPC Peering ----------
# 같은 계정/같은 리전이라 auto_accept = true로 요청과 수락이 한 리소스 안에서
# 동시에 처리된다(다른 계정 간이었다면 aws_vpc_peering_connection_accepter가
# 상대 계정 쪽에 별도로 필요).
resource "aws_vpc_peering_connection" "keycloak_to_demo" {
  vpc_id      = aws_vpc.keycloak.id
  peer_vpc_id = aws_vpc.main.id
  auto_accept = true

  # 기본값(false)이면 Peering 너머 프라이빗 리소스를 DNS 이름으로 조회할 때
  # 퍼블릭 IP로 잘못 풀리거나 아예 안 풀린다 - Keycloak(프라이빗 서브넷)이
  # EKS 프라이빗 엔드포인트(04-eks.tf, endpoint_private_access=true)를 이름으로
  # 조회하려면 양쪽 다 켜야 한다.
  accepter {
    allow_remote_vpc_dns_resolution = true
  }
  requester {
    allow_remote_vpc_dns_resolution = true
  }

  tags = {
    Name = "${local.name_prefix}-keycloak-to-demo-peering"
  }
}

# demo VPC 쪽 라우팅 테이블에도 Keycloak VPC로 가는 경로를 추가해야 양방향
# 통신이 된다(Peering은 연결만으로는 트래픽이 안 흐르고, 양쪽 라우팅 테이블에
# 각각 상대 CIDR을 명시해야 함).
resource "aws_route" "demo_public_to_keycloak" {
  route_table_id            = aws_route_table.public.id
  destination_cidr_block    = var.keycloak_vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection.keycloak_to_demo.id
}

resource "aws_route" "demo_private_to_keycloak" {
  count                      = length(aws_route_table.private)
  route_table_id             = aws_route_table.private[count.index].id
  destination_cidr_block     = var.keycloak_vpc_cidr
  vpc_peering_connection_id  = aws_vpc_peering_connection.keycloak_to_demo.id
}

output "keycloak_vpc_id" {
  value = aws_vpc.keycloak.id
}

output "vpc_peering_connection_id" {
  value = aws_vpc_peering_connection.keycloak_to_demo.id
}
