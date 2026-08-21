# =============================================================================
# 네트워크 (VPC)
# =============================================================================
# 구조: 퍼블릭 서브넷(ALB, NAT) + 프라이빗 앱 서브넷(EKS) + 프라이빗 DB 서브넷(RDS)
# 각 계층마다 서브넷을 나눠서, DB는 인터넷에서 절대 직접 접근할 수 없게 합니다.

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

# ---------- 퍼블릭 서브넷 (ALB용) ----------
resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                                 = "${local.name_prefix}-public-subnet-${local.azs[count.index]}"
    "kubernetes.io/role/elb"                             = "1" # ALB Controller가 인터넷용 ALB를 여기 배치
    "kubernetes.io/cluster/${local.name_prefix}-cluster" = "shared"
  }
}

# ---------- 프라이빗 앱 서브넷 (EKS 노드용) ----------
resource "aws_subnet" "private_app" {
  count             = length(var.private_app_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_app_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name                                                 = "${local.name_prefix}-private-app-subnet-${local.azs[count.index]}"
    "kubernetes.io/role/internal-elb"                    = "1"
    "kubernetes.io/cluster/${local.name_prefix}-cluster" = "shared"
  }
}

# ---------- 프라이빗 DB 서브넷 (RDS용) ----------
resource "aws_subnet" "private_db" {
  count             = length(var.private_db_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_db_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${local.name_prefix}-private-db-subnet-${local.azs[count.index]}"
  }
}

# ---------- NAT Gateway (프라이빗 서브넷이 인터넷 나갈 때 사용: 이미지 pull 등) ----------
resource "aws_eip" "nat" {
  count  = var.single_nat_gateway ? 1 : length(local.azs)
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count         = var.single_nat_gateway ? 1 : length(local.azs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "${local.name_prefix}-nat-gw-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# ---------- 라우팅 테이블 ----------
# ⚠️ 이 라우팅 테이블들의 route는 반드시 독립된 aws_route 리소스로만 추가할 것
# (인라인 route 블록 금지). 15-keycloak-vpc-peering.tf가 같은 라우트 테이블에
# 피어링 라우트를 별도 aws_route 리소스로 얹기 때문에, 인라인 route를 쓰면
# 그 피어링 라우트를 "설정에 없는 드리프트"로 오인해 apply 때마다 삭제하고
# Keycloak/Pomerium ↔ EKS 간 연결이 끊긴다.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-public-rt"
  }
}

resource "aws_route" "public_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id              = aws_internet_gateway.main.id
}

resource "aws_route_table" "private" {
  count  = length(local.azs)
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-private-rt-${local.azs[count.index]}"
  }
}

resource "aws_route" "private_nat" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id          = var.single_nat_gateway ? aws_nat_gateway.main[0].id : aws_nat_gateway.main[count.index].id
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_app" {
  count          = length(aws_subnet.private_app)
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "private_db" {
  count          = length(aws_subnet.private_db)
  subnet_id      = aws_subnet.private_db[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
