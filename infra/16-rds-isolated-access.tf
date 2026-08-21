# =============================================================================
# HR RDS 조회 전용 격리 서브넷 (인터넷 경로 없음)
# =============================================================================
# CloudShell VPC 환경은 UI의 업로드/다운로드 버튼은 막히지만, 그 서브넷에
# 인터넷 경로(NAT/IGW)가 있으면 CLI 도구(curl, aws s3 cp 등)로 여전히 파일을
# 빼돌릴 수 있다(AWS 공식 문서에 명시된 사실). 기존 private_app/private_db
# 서브넷은 도커 이미지 pull 등을 위해 NAT로 인터넷이 열려있어서 이 용도에
# 못 쓴다.
#
# 이 서브넷은 라우팅 테이블에 로컬(VPC 내부) 경로 말고는 아무 것도 없다 -
# 즉 RDS 등 같은 VPC 안의 리소스로는 갈 수 있지만, 인터넷으로는 전혀 못
# 나간다. HR RDS를 조회할 CloudShell VPC 환경은 반드시 이 서브넷을 선택할 것.
#
# 사용법(콘솔에서 수동으로 해야 함 - CloudShell VPC 환경은 Terraform 리소스로
# 없음): CloudShell → Create VPC environment → VPC: 이 VPC, Subnet: 아래
# aws_subnet.rds_readonly_isolated, Security group: rds_sg를 참조하는 SG나
# 5432 아웃바운드만 허용하는 전용 SG.

resource "aws_subnet" "rds_readonly_isolated" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.200.0/24"
  availability_zone = local.azs[0]

  tags = {
    Name = "${local.name_prefix}-rds-readonly-isolated-subnet"
  }
}

resource "aws_route_table" "rds_readonly_isolated" {
  vpc_id = aws_vpc.main.id
  # 의도적으로 route 블록이 없음 - 로컬(VPC 내부) 라우팅만 암묵적으로 적용됨.
  # 0.0.0.0/0 라우팅을 추가하는 순간 이 서브넷의 격리 목적이 깨짐.

  tags = {
    Name = "${local.name_prefix}-rds-readonly-isolated-rt"
  }
}

resource "aws_route_table_association" "rds_readonly_isolated" {
  subnet_id      = aws_subnet.rds_readonly_isolated.id
  route_table_id = aws_route_table.rds_readonly_isolated.id
}

# 이 서브넷에서 뜨는 CloudShell VPC 환경에 붙일 보안그룹. RDS 5432로 나가는 것만
# 허용(그 외 아웃바운드 전부 차단 - 어차피 라우팅 테이블에 인터넷 경로 자체가
# 없어서 의미는 없지만, 방어를 이중으로 걸어둠).
resource "aws_security_group" "rds_readonly_cloudshell" {
  name = "${local.name_prefix}-rds-readonly-cloudshell-sg"
  # (한글: HR RDS 조회 전용 CloudShell VPC 환경용 - RDS(5432)로만 아웃바운드 허용)
  # AWS security group description은 ASCII만 허용하므로(한글 불가), description은
  # 영문으로 쓰고 실제 설명은 이 주석으로 남긴다.
  description = "HR RDS read-only CloudShell VPC environment - outbound to RDS(5432) only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-rds-readonly-cloudshell-sg"
  }
}

resource "aws_vpc_security_group_egress_rule" "rds_readonly_cloudshell_to_rds" {
  security_group_id           = aws_security_group.rds_readonly_cloudshell.id
  referenced_security_group_id = aws_security_group.rds_sg.id
  from_port                   = 5432
  to_port                     = 5432
  ip_protocol                 = "tcp"
  description                 = "PostgreSQL only"
}

output "rds_readonly_isolated_subnet_id" {
  description = "HR RDS 조회 전용 CloudShell VPC 환경을 만들 때 선택할 서브넷"
  value       = aws_subnet.rds_readonly_isolated.id
}

output "rds_readonly_cloudshell_sg_id" {
  description = "위 CloudShell VPC 환경에 붙일 보안그룹"
  value       = aws_security_group.rds_readonly_cloudshell.id
}
