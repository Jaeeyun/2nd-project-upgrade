# =============================================================================
# Pomerium PoC (Keycloak VPC에 배치, 나중에 온프레미스+VPN 구조로 교체 예정)
# =============================================================================
# Keycloak을 처음 AWS로 옮겨서 테스트했던 것과 같은 논리: 진짜로는 온프레미스에
# 올라갈 물건이지만, 지금은 이미 만들어둔 Keycloak VPC(퍼블릭 서브넷 + Peering)에
# 같이 둬서 "온프레미스 대역에서 사설 경로로 데모 VPC 안 리소스와 통신한다"는
# 최종 그림을 저비용으로 미리 검증한다.
#
# Keycloak 부트스트랩(11-keycloak.tf/keycloak-bootstrap.sh.tpl)은 안 건드리고,
# Pomerium 쪽 부트스트랩 스크립트가 Keycloak의 HTTPS Admin API
# (https://<keycloak_private_ip>/admin/...)를 직접 호출해서 스스로 OIDC 클라이언트를
# 등록한다 - Keycloak 컨테이너 내부에 들어갈 필요 없음. Keycloak이 프라이빗
# 서브넷으로 옮겨간 뒤로는(15-keycloak-vpc-peering.tf) 이 Admin API 호출은
# 애초에 사설 IP로만 가능하다(퍼블릭 경로 자체가 없음).

resource "aws_security_group" "pomerium" {
  name        = "${local.name_prefix}-pomerium-sg"
  description = "Pomerium EC2 - HTTPS only from admin CIDR, no SSH"
  vpc_id      = aws_vpc.keycloak.id
}

resource "aws_vpc_security_group_ingress_rule" "pomerium_https_from_admin" {
  count             = length(var.keycloak_admin_cidr)
  security_group_id = aws_security_group.pomerium.id
  cidr_ipv4         = var.keycloak_admin_cidr[count.index]
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# HR 앱 Pod가 Pomerium의 /.well-known/pomerium/jwks.json을 직접 조회해서
# x-pomerium-jwt-assertion 서명을 검증하기 위해 필요(평문 X-Pomerium-Claim-Email
# 헤더는 클라이언트가 위조 가능해서 더 이상 신뢰하지 않음, auth.py 참고).
resource "aws_vpc_security_group_ingress_rule" "pomerium_https_from_main_vpc" {
  security_group_id = aws_security_group.pomerium.id
  cidr_ipv4          = var.vpc_cidr
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "pomerium_out" {
  security_group_id = aws_security_group.pomerium.id
  cidr_ipv4          = "0.0.0.0/0"
  ip_protocol        = "-1" # Keycloak(같은 VPC) + 내부 ALB(Peering 경유) 둘 다 필요해서 전체 허용
}

# Keycloak SG에 "Pomerium에서 오는 443만 추가로 허용" - SG-to-SG 참조(ADR-012 결정 2)
resource "aws_vpc_security_group_ingress_rule" "keycloak_https_from_pomerium" {
  security_group_id            = aws_security_group.keycloak.id
  referenced_security_group_id = aws_security_group.pomerium.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_iam_role" "pomerium_ec2" {
  name = "${local.name_prefix}-pomerium-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "pomerium_ssm_core" {
  role       = aws_iam_role.pomerium_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Keycloak admin 비밀번호를 읽어야 Admin API로 OIDC 클라이언트를 등록할 수 있음
data "aws_iam_policy_document" "pomerium_read_keycloak_admin_password" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:*:*:parameter/keycloak/${local.name_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "pomerium_read_keycloak_admin_password" {
  name   = "pomerium-read-keycloak-admin-password"
  role   = aws_iam_role.pomerium_ec2.id
  policy = data.aws_iam_policy_document.pomerium_read_keycloak_admin_password.json
}

resource "aws_iam_instance_profile" "pomerium" {
  name = "${local.name_prefix}-pomerium-ec2-profile"
  role = aws_iam_role.pomerium_ec2.name
}

resource "aws_instance" "pomerium" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.keycloak_instance_type
  subnet_id                   = aws_subnet.keycloak_public.id
  vpc_security_group_ids      = [aws_security_group.pomerium.id]
  iam_instance_profile        = aws_iam_instance_profile.pomerium.name
  # Pomerium은 자신의 OIDC 클라이언트("pomerium")를 Keycloak에 최초 부팅 시
  # 한 번만 등록한다(pomerium-bootstrap.sh.tpl). Keycloak 인스턴스가
  # 재생성되면(11-keycloak.tf의 user_data_replace_on_change) 내용이 바뀌므로,
  # Pomerium도 함께 재생성돼야 새 Keycloak에 재등록된다 - 이 값이 true라야
  # Keycloak의 user_data가 바뀔 때(ALB DNS 이름은 안정적이지만 admin 비밀번호
  # 등은 매번 새로 생성됨) Pomerium도 같이 재생성된다.
  user_data_replace_on_change = true

  metadata_options {
    http_tokens                 = "required"
    http_endpoint                = "enabled"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/pomerium-bootstrap.sh.tpl", {
    region              = var.aws_region
    name_prefix          = local.name_prefix
    # idp_provider_url(OIDC discovery/token 서버간 통신 + 최종 사용자
    # 브라우저의 로그인 리다이렉트 둘 다 이 주소를 씀)엔 Keycloak ALB의 DNS
    # 이름을 쓴다. Pomerium은 Keycloak과 같은 VPC의 퍼블릭 서브넷에 있어서
    # (실제 인터넷 라우팅 경유) ALB로 나가는 데 지장이 없다 - 예전에 EC2
    # 퍼블릭 IP를 직접 쓸 때 겪었던 "같은 VPC 안에서 EC2 퍼블릭 IP끼리
    # 접근 시 응답 없음(hairpin)" 문제는 EC2 자체의 1:1 NAT 특성 때문이었고,
    # ALB는 그 제약이 없다(ALB는 별도 ENI 기반의 진짜 퍼블릭 엔드포인트).
    # [검증 필요] 실제 재배포 시 이 경로(Pomerium→Keycloak ALB, 같은 VPC 안)가
    # 정말 문제없이 동작하는지는 라이브로 재확인 안 했다 - 만약 여기서도
    # 비슷한 문제가 나면 Pomerium 쪽 hosts 파일에 이 도메인을 Keycloak
    # private IP로 강제 매핑하는 우회가 필요할 수 있다.
    keycloak_endpoint    = aws_lb.keycloak.dns_name
    # Admin API/토큰 교환 등 서버간 호출은 원래도 private IP를 썼고, 이제는
    # Keycloak이 프라이빗 서브넷이라 오히려 이 경로가 유일하게 가능한
    # 경로다(퍼블릭 IP 자체가 없음).
    keycloak_private_ip = aws_instance.keycloak.private_ip
    realm_name           = var.keycloak_realm_name
    alb_dns_name         = aws_lb.internal_mtls.dns_name
    ca_cert_pem          = tls_self_signed_cert.mtls_ca.cert_pem
    client_cert_pem      = tls_locally_signed_cert.pomerium_client.cert_pem
    client_key_pem       = tls_private_key.pomerium_client.private_key_pem
  })

  tags = {
    Name = "${local.name_prefix}-pomerium-poc"
  }

  depends_on = [
    # aws_instance.keycloak 하나만 의존하면 "EC2가 생성되기 시작함"만 보장되고
    # "Keycloak 부트스트랩 스크립트가 다 끝나 SSM에 최신 admin 비밀번호까지
    # 저장됨"은 보장되지 않는다 - null_resource.wait_for_keycloak(SAML
    # descriptor가 응답할 때까지 폴링, 부트스트랩 완료의 확실한 신호)에
    # 의존해야 Pomerium이 Keycloak 준비 완료 후에만 생성된다.
    null_resource.wait_for_keycloak,
    aws_lb_listener.internal_mtls_https,
  ]
}

output "pomerium_public_ip" {
  value = aws_instance.pomerium.public_ip
}

output "pomerium_login_url" {
  description = "브라우저로 열면 Pomerium이 Keycloak 로그인으로 리다이렉트 후, 통과하면 내부 ALB(echo 백엔드)로 프록시"
  value       = "https://${aws_instance.pomerium.public_ip}/"
}
