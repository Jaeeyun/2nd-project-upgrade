# =============================================================================
# Keycloak (ADR-001 PoC) - 프라이빗 서브넷 EC2 + 퍼블릭 ALB, 단일 apply로 통합
# =============================================================================
# ⚠️ 사전 준비(수동, 최초 1회 또는 이미지 버전 올릴 때마다): 이 인스턴스는
# 프라이빗 서브넷이라 인터넷에서 이미지를 직접 pull할 수 없다. terraform apply
# 전에 scripts/mirror-keycloak-image-to-ecr.sh를 먼저 실행해서 Keycloak
# 이미지를 이 계정 ECR로 미러링해둬야 한다(그 스크립트 자체 주석에 순서 있음).
#
# 원래 PoC(README)는 "Keycloak API가 살아있어야 Realm/Client 설정 가능 → 그
# 메타데이터가 있어야 AWS SAML Provider 등록 가능"이라는 구조적 제약 때문에
# stage-1(EC2)/stage-2(keycloak provider)/stage-3(AWS IAM)로 apply를 3번 나눴다.
#
# 이번엔 다음 두 가지로 그 제약을 우회해서 하나의 apply 안에 넣는다.
#   1. stage-2(Realm/Client/매퍼/테스트유저 생성)를 keycloak Terraform provider가
#      아니라 EC2 user_data 안의 kcadm.sh(Keycloak 자체 admin CLI)로 옮긴다.
#      → keycloak provider의 "URL이 apply 시점에 이미 살아있어야 함" 제약 자체가
#        사라진다 (keycloak-bootstrap.sh.tpl 참고).
#   2. IAM Role ARN과 SAML Provider ARN은 AWS가 리소스 생성 후 반환하는 값이
#      아니라, 우리가 이름을 직접 정하기 때문에 "arn:aws:iam::<account>:role/<name>"
#      형태로 100% 예측 가능하다. 그래서 실제 aws_iam_role/aws_iam_saml_provider
#      리소스가 아직 생성되기 전이라도, EC2 user_data에는 이 "계산된 문자열"만
#      넘겨주면 된다 (실제 리소스 생성 완료를 기다릴 필요가 없음).
#
# 다만 "Keycloak이 Realm/Client 생성까지 끝냈다"는 사실 자체는 Terraform이
# 알 방법이 없으므로(EC2가 running 상태가 됐다고 user_data도 끝난 건 아님),
# null_resource.wait_for_keycloak이 SAML descriptor 엔드포인트를 직접 폴링해서
# "준비 완료" 신호로 삼는다. 이 폴링은 terraform apply를 실행하는 머신에서
# 앞단 ALB(아래 aws_lb.keycloak)로 나가므로, var.keycloak_admin_cidr에 그
# 머신의 공인 IP가 포함되어 있어야 한다(EC2 자체엔 이제 직접 못 감).
#
# [2026-08 재설계] EC2는 원래 퍼블릭 서브넷에 있었다 - 왜 프라이빗+ALB로
# 바꿨는지는 15-keycloak-vpc-peering.tf 상단 주석 참고.

locals {
  saml_provider_name     = "${local.name_prefix}-keycloak"
  saml_provider_arn      = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:saml-provider/${local.saml_provider_name}"
  # ADR-019: 5종 → 8종(직무 3개(dev/db/ops) × 신뢰도 2단계 + dev-hr-backend 전용 + 감사)으로 재확장.
  keycloak_role_names = {
    dev-general       = "${local.name_prefix}-dev-general"
    dev-lead          = "${local.name_prefix}-dev-lead"
    dev-hr-backend    = "${local.name_prefix}-dev-hr-backend"
    db-general        = "${local.name_prefix}-db-general"
    db-lead           = "${local.name_prefix}-db-lead"
    ops-general       = "${local.name_prefix}-ops-general"
    ops-lead          = "${local.name_prefix}-ops-lead"
    security-auditor  = "${local.name_prefix}-security-auditor"
  }
  keycloak_role_arns = {
    for k, name in local.keycloak_role_names :
    k => "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${name}"
  }
}

# ---------- 보안그룹 (ADR-002/012: SSH 없음, 기능 단위 분리) ----------
# 15-keycloak-vpc-peering.tf에서 만든 별도 VPC(퍼블릭 서브넷)에 둔다. 네트워크
# 계층에서는 여전히 인터넷에 노출된 퍼블릭 서브넷이고, 이 SG(admin CIDR만 허용)로
# 접근을 걸러내는 구조다 - PoC 목적상 진짜 private subnet+NAT Gateway까지는
# 두지 않기로 함(비용 대비 검증 목적 초과 판단).
resource "aws_security_group" "keycloak" {
  name        = "${local.name_prefix}-keycloak-sg"
  description = "Keycloak EC2 - HTTPS only from its own ALB, no SSH (ADR-002)"
  vpc_id      = aws_vpc.keycloak.id

  tags = {
    Name = "${local.name_prefix}-keycloak-sg"
    Role = "keycloak"
  }
}

# 예전엔 admin CIDR을 이 SG에 직접 허용했는데(인스턴스가 퍼블릭 서브넷에
# 있었으므로), 이제 인스턴스는 프라이빗 서브넷이라 직접 도달 자체가
# 불가능하다 - admin CIDR 필터링은 앞단 ALB의 SG(keycloak_alb, 아래)로
# 옮겨가고, 인스턴스 SG는 "그 ALB에서 오는 트래픽만" 허용하면 된다
# (SG-to-SG 참조, ADR-012 결정 2와 동일 패턴).
resource "aws_vpc_security_group_ingress_rule" "keycloak_https_from_alb" {
  security_group_id            = aws_security_group.keycloak.id
  referenced_security_group_id = aws_security_group.keycloak_alb.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "HTTPS from Keycloak ALB only"
}

# session-revoke Lambda(35-session-revocation.tf)가 관리자 API로 강제 로그아웃을
# 걸 때 이 경로로 들어온다 - Lambda가 VPC(private_app)에 붙어 피어링 사설
# 경로로 접속하므로, 위 ALB 규칙과 별개로 demo VPC 대역을 허용해야 함
# (Lambda가 VPC에 안 붙어있으면 발신지가 AWS 공용 IP 풀이라 이 규칙에
# 안 걸려 접속 자체가 타임아웃남). 이건 ALB를 거치지 않는 사설 경로라
# 그대로 유지한다.
resource "aws_vpc_security_group_ingress_rule" "keycloak_https_from_main_vpc" {
  security_group_id = aws_security_group.keycloak.id
  cidr_ipv4          = var.vpc_cidr
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
  description        = "HTTPS from demo VPC via peering (session-revoke Lambda admin API calls)"
}

# 프라이빗 서브넷이라 실제로 나갈 수 있는 곳은 같은 VPC 안의 VPC 엔드포인트
# (ECR/SSM/S3)뿐이다 - 라우팅 테이블에 인터넷으로 가는 경로 자체가 없어서
# 0.0.0.0/0을 허용해도 실질적으로 VPC 밖으로는 못 나간다. 그래도 명시적으로
# 어디로 나가는 트래픽인지 남겨두기 위해 목적지를 좁혀뒀다.
resource "aws_vpc_security_group_egress_rule" "keycloak_https_out" {
  security_group_id            = aws_security_group.keycloak.id
  referenced_security_group_id = aws_security_group.keycloak_vpc_endpoints.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "HTTPS to Interface VPC endpoints only (ECR API/DKR, SSM)"
}

# S3 Gateway 엔드포인트(ECR 이미지 레이어의 실제 저장소, 14-keycloak-vpc-endpoints.tf)는
# ENI가 없는 라우팅 테이블 기반 엔드포인트라 위 SG 참조로는 안 걸린다 -
# AWS 관리형 프리픽스 리스트로 목적지를 지정해야 한다. 이게 없으면 ECR API
# 호출(매니페스트 조회)까지는 되는데 실제 이미지 레이어(blob) 다운로드
# 단계에서 막혀 docker pull이 중간에 멈춘다.
data "aws_prefix_list" "s3" {
  name = "com.amazonaws.${var.aws_region}.s3"
}

resource "aws_vpc_security_group_egress_rule" "keycloak_https_to_s3" {
  security_group_id = aws_security_group.keycloak.id
  prefix_list_id     = data.aws_prefix_list.s3.id
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
  description        = "HTTPS to S3 Gateway endpoint (ECR image layers)"
}

# =============================================================================
# 퍼블릭 ALB (Keycloak 프라이빗 서브넷 이전에 따른 새 진입점)
# =============================================================================
# 예전엔 브라우저(관리자, SAML 로그인하는 최종 사용자)가 Keycloak EC2의
# 퍼블릭 IP로 직접 접속했다. 이제 EC2는 프라이빗이라 그 경로가 아예 없고,
# 이 ALB가 유일한 진입점이다. admin CIDR 필터링도 여기(ALB SG)로 옮겨왔다 -
# 접근 통제 정책 자체는 그대로고(같은 CIDR만 허용), 집행 지점만 EC2 SG에서
# ALB SG로 이동했을 뿐이다.
resource "aws_security_group" "keycloak_alb" {
  name        = "${local.name_prefix}-keycloak-alb-sg"
  description = "Keycloak ALB - HTTPS only from admin CIDR"
  vpc_id      = aws_vpc.keycloak.id

  tags = {
    Name = "${local.name_prefix}-keycloak-alb-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "keycloak_alb_https_from_admin" {
  count             = length(var.keycloak_admin_cidr)
  security_group_id = aws_security_group.keycloak_alb.id
  cidr_ipv4         = var.keycloak_admin_cidr[count.index]
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS from admin CIDR only"
}

resource "aws_vpc_security_group_egress_rule" "keycloak_alb_to_instance" {
  security_group_id            = aws_security_group.keycloak_alb.id
  referenced_security_group_id = aws_security_group.keycloak.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# ---------- ALB 서버 인증서 (자체 서명 CA, 32-mtls-alb.tf와 동일 패턴) ----------
# 실제 도메인이 있는 배포라면 이 블록 전체를 지우고 aws_acm_certificate에
# validation_method="DNS"인 진짜 퍼블릭 인증서로 교체할 것 - 자체서명 인증서로는
# 이 ALB에 접속하는 모든 브라우저(SAML 로그인하는 최종 사용자 포함)가 경고를
# 본다. PoC 범위상 여기서는 그대로 둔다.
resource "tls_private_key" "keycloak_alb_ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "keycloak_alb_ca" {
  private_key_pem = tls_private_key.keycloak_alb_ca.private_key_pem

  subject {
    common_name  = "${local.name_prefix}-keycloak-alb-ca"
    organization = "PoC Internal CA"
  }

  validity_period_hours = 24 * 30
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
    "key_encipherment",
  ]
}

resource "tls_private_key" "keycloak_alb_server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "keycloak_alb_server" {
  private_key_pem = tls_private_key.keycloak_alb_server.private_key_pem

  subject {
    common_name = aws_lb.keycloak.dns_name
  }

  dns_names = [aws_lb.keycloak.dns_name]
}

resource "tls_locally_signed_cert" "keycloak_alb_server" {
  cert_request_pem   = tls_cert_request.keycloak_alb_server.cert_request_pem
  ca_private_key_pem = tls_private_key.keycloak_alb_ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.keycloak_alb_ca.cert_pem

  validity_period_hours = 24 * 30

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "keycloak_alb" {
  private_key       = tls_private_key.keycloak_alb_server.private_key_pem
  certificate_body  = tls_locally_signed_cert.keycloak_alb_server.cert_pem
  certificate_chain = tls_self_signed_cert.keycloak_alb_ca.cert_pem
}

resource "aws_lb" "keycloak" {
  name               = trimsuffix(substr("${local.name_prefix}-keycloak-alb", 0, 32), "-")
  internal           = false # 유일하게 인터넷에 노출되는 지점 - EC2는 이제 아님
  load_balancer_type = "application"
  subnets            = [aws_subnet.keycloak_public.id]
  security_groups    = [aws_security_group.keycloak_alb.id]

  drop_invalid_header_fields = true # Security Hub ELB.4 대응
}

# target_type="instance"라 단일 EC2를 직접 등록한다(ASG가 아니라서 자동 등록
# 안 됨). 프로토콜을 HTTPS로 둬서 ALB→EC2 구간도 평문 없이 재암호화된다 -
# EC2가 제시하는 자체서명 인증서는 opportunistic TLS라 ALB가 체인 검증을
# 강제하지 않는다(target_group에 별도 트러스트스토어 설정이 없으면 그냥
# 연결만 확인).
resource "aws_lb_target_group" "keycloak" {
  name        = trimsuffix(substr("${local.name_prefix}-keycloak-tg", 0, 32), "-")
  port        = 443
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = aws_vpc.keycloak.id

  health_check {
    protocol = "HTTPS"
    path     = "/realms/master"
    matcher  = "200"
  }
}

resource "aws_lb_target_group_attachment" "keycloak" {
  target_group_arn = aws_lb_target_group.keycloak.arn
  target_id        = aws_instance.keycloak.id
  port              = 443
}

resource "aws_lb_listener" "keycloak_https" {
  load_balancer_arn = aws_lb.keycloak.arn
  port               = 443
  protocol           = "HTTPS"
  certificate_arn    = aws_acm_certificate.keycloak_alb.arn
  ssl_policy         = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.keycloak.arn
  }
}

output "keycloak_alb_dns_name" {
  description = "Keycloak 로그인 화면/SAML descriptor의 새 진입점 (예전 keycloak_public_ip를 대체)"
  value       = aws_lb.keycloak.dns_name
}

# ---------- IAM Role + Instance Profile (ADR-011: 전용 Role, SSM 최소권한) ----------
data "aws_iam_policy_document" "ec2_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "keycloak_ec2" {
  name               = "${local.name_prefix}-keycloak-ec2-role"
  description        = "ADR-011: Keycloak EC2 dedicated Instance Profile, SSM management only"
  assume_role_policy = data.aws_iam_policy_document.ec2_trust.json
}

resource "aws_iam_role_policy_attachment" "keycloak_ssm_core" {
  role       = aws_iam_role.keycloak_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# admin 비밀번호는 SSM Parameter Store(SecureString)에만 쓰도록 범위 제한
data "aws_iam_policy_document" "keycloak_admin_password_ssm" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:PutParameter", "ssm:GetParameter"]
    resources = ["arn:aws:ssm:*:*:parameter/keycloak/${local.name_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "keycloak_admin_password_ssm" {
  name   = "keycloak-admin-password-ssm"
  role   = aws_iam_role.keycloak_ec2.id
  policy = data.aws_iam_policy_document.keycloak_admin_password_ssm.json
}

resource "aws_iam_instance_profile" "keycloak" {
  name = "${local.name_prefix}-keycloak-ec2-profile"
  role = aws_iam_role.keycloak_ec2.name
}

# ---------- EC2 인스턴스 (퍼블릭 서브넷) ----------
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "keycloak" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.keycloak_instance_type
  subnet_id                   = aws_subnet.keycloak_private.id
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.keycloak.id]
  iam_instance_profile        = aws_iam_instance_profile.keycloak.name
  # EC2 user_data는 최초 부팅 시 한 번만 실행되므로, 기본값(false)이면
  # 부트스트랩 스크립트를 고쳐도 이미 떠있는 인스턴스에는 반영되지 않는다.
  # true로 켜서 스크립트가 바뀌면 인스턴스를 재생성해 항상 최신 스크립트로
  # 부팅되게 한다.
  user_data_replace_on_change = true

  # ADR-011: IMDSv2 강제
  metadata_options {
    http_tokens                 = "required"
    http_endpoint                = "enabled"
    http_put_response_hop_limit = 1
  }

  user_data = templatefile("${path.module}/keycloak-bootstrap.sh.tpl", {
    region                     = var.aws_region
    name_prefix                = local.name_prefix
    realm_name                 = var.keycloak_realm_name
    dev_general_role_arn       = local.keycloak_role_arns["dev-general"]
    dev_lead_role_arn          = local.keycloak_role_arns["dev-lead"]
    dev_hr_backend_role_arn    = local.keycloak_role_arns["dev-hr-backend"]
    db_general_role_arn        = local.keycloak_role_arns["db-general"]
    db_lead_role_arn           = local.keycloak_role_arns["db-lead"]
    ops_general_role_arn       = local.keycloak_role_arns["ops-general"]
    ops_lead_role_arn          = local.keycloak_role_arns["ops-lead"]
    security_auditor_role_arn  = local.keycloak_role_arns["security-auditor"]
    saml_provider_arn          = local.saml_provider_arn
    test_user_password         = var.keycloak_test_users_password
    # 프라이빗 서브넷 전환으로 새로 필요해진 값들 - quay.io 대신 여기서 pull하고,
    # 퍼블릭 IP가 없어져서 인증서 SAN도 ALB DNS 이름 기준으로 만들어야 한다.
    ecr_repository_url        = aws_ecr_repository.keycloak_mirror.repository_url
    alb_dns_name               = aws_lb.keycloak.dns_name
  })

  tags = {
    Name = "${local.name_prefix}-keycloak-poc"
    Role = "keycloak"
  }

  depends_on = [
    aws_iam_role_policy_attachment.keycloak_ssm_core,
    aws_iam_role_policy.keycloak_admin_password_ssm,
    aws_iam_role_policy.keycloak_ecr_pull,
    aws_vpc_endpoint.keycloak_interface,
    aws_vpc_endpoint.keycloak_s3,
  ]
}

# ---------- 부트스트랩 완료 대기 ----------
# Realm/Client/매퍼/테스트유저 생성까지 끝나야만 SAML descriptor가 실제 값을
# 반환하므로, 이 폴링 자체가 "부트스트랩 완료" 신호가 된다. 이 명령은 terraform
# apply를 실행하는 머신에서 실행되므로 curl이 설치되어 있어야 하고, 그 머신의
# 공인 IP가 var.keycloak_admin_cidr에 포함되어 있어야 한다(ALB SG가 막으면
# 계속 실패). 예전엔 인스턴스 퍼블릭 IP를 직접 쳤는데, 이제 그 경로 자체가
# 없어져서 ALB DNS 이름으로 나가고, 타겟그룹에 EC2가 실제로 healthy로
# 등록된 뒤에야 의미가 있으므로 target_group_attachment에도 의존한다.
resource "null_resource" "wait_for_keycloak" {
  depends_on = [
    aws_instance.keycloak,
    aws_lb_listener.keycloak_https,
    aws_lb_target_group_attachment.keycloak,
  ]

  triggers = {
    instance_id = aws_instance.keycloak.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      echo "Keycloak SAML descriptor 준비 대기 중 (최대 ~15분)..."
      for i in $(seq 1 90); do
        STATUS=$(curl -sk -o /dev/null -w "%%{http_code}" "https://${aws_lb.keycloak.dns_name}/realms/${var.keycloak_realm_name}/protocol/saml/descriptor" || echo "000")
        if [ "$STATUS" = "200" ]; then
          echo "Keycloak 준비 완료 (descriptor 200 OK)"
          exit 0
        fi
        echo "  아직 준비 안 됨 (status=$STATUS), 10초 후 재시도... ($i/90)"
        sleep 10
      done
      echo "타임아웃: Keycloak이 15분 내에 준비되지 않았습니다. var.keycloak_admin_cidr에 이 머신의 공인 IP가 포함되어 있는지, ALB 타겟그룹이 healthy인지, SSM으로 접속해 user_data 로그(/var/log/cloud-init-output.log)를 확인하세요." >&2
      exit 1
    EOT
  }
}

# ---------- SAML 메타데이터 수집 ----------
data "http" "keycloak_saml_metadata" {
  url      = "https://${aws_lb.keycloak.dns_name}/realms/${var.keycloak_realm_name}/protocol/saml/descriptor"
  insecure = true # PoC 전용 자체서명 인증서 - 정식 도입 시 ACM 교체 후 제거

  depends_on = [null_resource.wait_for_keycloak]
}

# ---------- AWS IAM SAML Identity Provider 등록 ----------
resource "aws_iam_saml_provider" "keycloak" {
  name                   = local.saml_provider_name
  saml_metadata_document = data.http.keycloak_saml_metadata.response_body
}

output "keycloak_idp_initiated_sso_login_url" {
  description = "ADR-001 결정 2번: 이 링크를 클릭하면 별도 백엔드 없이 AWS Console로 바로 진입"
  value       = "https://${aws_lb.keycloak.dns_name}/realms/${var.keycloak_realm_name}/protocol/saml/clients/aws"
}

output "keycloak_admin_password_ssm_parameter" {
  description = "Keycloak admin 비밀번호가 저장된 SSM Parameter 이름"
  value       = "/keycloak/${local.name_prefix}/admin-password"
}

output "keycloak_saml_provider_arn" {
  description = "AWS IAM에 등록된 Keycloak SAML Provider ARN"
  value       = aws_iam_saml_provider.keycloak.arn
}
