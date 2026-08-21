# =============================================================================
# mTLS 내부 ALB (Pomerium PoC) — Pomerium이 보낸 요청만 ALB가 받게 강제
# =============================================================================
# 이중 방어:
#   1) 네트워크 계층: ALB 보안그룹이 Keycloak VPC(Pomerium이 있는 곳) CIDR에서만
#      443 인바운드를 허용
#   2) TLS 계층: ALB 리스너에 mTLS(mutual_authentication)를 걸어, 우리가 만든
#      CA로 서명된 클라이언트 인증서를 제시하지 못하면 TLS 핸드셰이크 자체가
#      거부됨 - 네트워크 계층을 어떻게든 우회해도 인증서 없이는 못 들어옴
#
# 백엔드는 아직 실제 배포된 앱(HR 사이트)이 없어서, "Pomerium이 보낸 요청이
# 실제로 여기까지 도달하고 헤더가 잘 전달되는지"만 확인할 수 있는 간단한 echo
# Lambda를 붙여뒀습니다. 나중에 실제 앱이 배포되면 이 target_group을 그
# Service로 바꾸면 됩니다.

# ---------- CA (자체 서명, PoC 전용) ----------
resource "tls_private_key" "mtls_ca" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "tls_self_signed_cert" "mtls_ca" {
  private_key_pem = tls_private_key.mtls_ca.private_key_pem

  subject {
    common_name  = "${local.name_prefix}-internal-ca"
    organization = "PoC Internal CA"
  }

  validity_period_hours = 24 * 30 # 30일, PoC 전용
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
    "key_encipherment",
  ]
}

# ---------- ALB 서버 인증서 (이 CA로 서명) ----------
resource "tls_private_key" "alb_server" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "alb_server" {
  private_key_pem = tls_private_key.alb_server.private_key_pem

  subject {
    common_name = aws_lb.internal_mtls.dns_name
  }

  dns_names = [aws_lb.internal_mtls.dns_name]
}

resource "tls_locally_signed_cert" "alb_server" {
  cert_request_pem   = tls_cert_request.alb_server.cert_request_pem
  ca_private_key_pem = tls_private_key.mtls_ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.mtls_ca.cert_pem

  validity_period_hours = 24 * 30

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "alb_server" {
  private_key       = tls_private_key.alb_server.private_key_pem
  certificate_body  = tls_locally_signed_cert.alb_server.cert_pem
  certificate_chain = tls_self_signed_cert.mtls_ca.cert_pem
}

# ---------- Pomerium용 클라이언트 인증서 (같은 CA로 서명) ----------
resource "tls_private_key" "pomerium_client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "pomerium_client" {
  private_key_pem = tls_private_key.pomerium_client.private_key_pem

  subject {
    common_name = "${local.name_prefix}-pomerium-client"
  }
}

resource "tls_locally_signed_cert" "pomerium_client" {
  cert_request_pem   = tls_cert_request.pomerium_client.cert_request_pem
  ca_private_key_pem = tls_private_key.mtls_ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.mtls_ca.cert_pem

  validity_period_hours = 24 * 30

  allowed_uses = [
    "digital_signature",
    "key_encipherment",
    "client_auth",
  ]
}

# ---------- CA 인증서를 ALB Trust Store용 S3에 업로드 ----------
resource "aws_s3_bucket" "mtls_trust_store" {
  bucket        = "${local.name_prefix}-mtls-trust-store-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "mtls_trust_store" {
  bucket                  = aws_s3_bucket.mtls_trust_store.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "mtls_ca_bundle" {
  bucket  = aws_s3_bucket.mtls_trust_store.id
  key     = "ca-bundle.pem"
  content = tls_self_signed_cert.mtls_ca.cert_pem
}

resource "aws_lb_trust_store" "pomerium_ca" {
  # AWS 하드 제한: 32자. name_prefix 길이에 따라 넘칠 수 있어 자동 절삭(끝에 "-"가
  # 남으면 리소스 생성 자체가 또 실패하므로 trimsuffix로 같이 정리).
  name                             = trimsuffix(substr("${local.name_prefix}-pomerium-ca-trust", 0, 32), "-")
  ca_certificates_bundle_s3_bucket = aws_s3_bucket.mtls_trust_store.id
  ca_certificates_bundle_s3_key    = aws_s3_object.mtls_ca_bundle.key
}

# ---------- 내부 ALB ----------
resource "aws_security_group" "internal_mtls_alb" {
  name        = "${local.name_prefix}-internal-mtls-alb-sg"
  # (한글: Pomerium(Keycloak VPC)에서만 443 인바운드 허용)
  description = "Allow inbound 443 only from Pomerium (Keycloak VPC)"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_ingress_rule" "internal_mtls_alb_from_pomerium_vpc" {
  security_group_id = aws_security_group.internal_mtls_alb.id
  cidr_ipv4          = var.keycloak_vpc_cidr # Pomerium이 이 VPC 안에 있음
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "internal_mtls_alb_out" {
  security_group_id = aws_security_group.internal_mtls_alb.id
  cidr_ipv4          = "0.0.0.0/0"
  ip_protocol        = "-1"
}

resource "aws_lb" "internal_mtls" {
  # AWS 하드 제한: 32자, 위와 동일한 이유로 자동 절삭
  name               = trimsuffix(substr("${local.name_prefix}-internal-mtls-alb", 0, 32), "-")
  internal           = true # 인터넷에 노출 안 됨 - Peering을 통한 사설 경로로만 도달 가능
  load_balancer_type = "application"
  subnets            = aws_subnet.private_app[*].id
  security_groups    = [aws_security_group.internal_mtls_alb.id]

  drop_invalid_header_fields = true # Security Hub ELB.4 대응
}

# ---------- ALB → EKS 노드/Pod 헬스체크 경로 허용 ----------
# EKS 노드는 03-security.tf의 aws_security_group.eks_nodes_sg가 아니라 EKS가
# 자동 생성하는 클러스터 SG를 쓴다(eks_nodes_sg는 죽은 리소스). 그 클러스터
# SG는 자기 자신에서 오는 트래픽만 기본 허용하므로, ALB가 Pod IP로 보내는
# 헬스체크가 통과하려면 ALB SG를 명시적으로 허용해야 한다.
resource "aws_vpc_security_group_ingress_rule" "eks_cluster_sg_from_internal_alb" {
  security_group_id            = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.internal_mtls_alb.id
  from_port                    = 80
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_lb_listener" "internal_mtls_https" {
  load_balancer_arn = aws_lb.internal_mtls.arn
  port               = 443
  protocol           = "HTTPS"
  certificate_arn    = aws_acm_certificate.alb_server.arn
  ssl_policy         = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  mutual_authentication {
    mode            = "verify" # 클라이언트 인증서 검증 필수 - 없으면 핸드셰이크 자체가 실패
    trust_store_arn = aws_lb_trust_store.pomerium_ca.arn
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.echo_backend.arn
  }
}

# ---------- 더미 백엔드: echo Lambda (실제 앱 배포 전까지 배관 확인용) ----------
data "archive_file" "alb_echo_target" {
  type        = "zip"
  source_file = "${path.module}/scripts/alb-echo-target.py"
  output_path = "${path.module}/.build/alb-echo-target.zip"
}

resource "aws_iam_role" "alb_echo_target" {
  name = "${local.name_prefix}-alb-echo-target-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "alb_echo_target_basic_logs" {
  role       = aws_iam_role.alb_echo_target.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "alb_echo_target" {
  function_name    = "${local.name_prefix}-alb-echo-target"
  role             = aws_iam_role.alb_echo_target.arn
  handler          = "alb-echo-target.handler"
  runtime          = "python3.12"
  timeout          = 10
  filename         = data.archive_file.alb_echo_target.output_path
  source_code_hash = data.archive_file.alb_echo_target.output_base64sha256
}

resource "aws_lambda_permission" "allow_alb_invoke" {
  statement_id  = "AllowALBInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alb_echo_target.function_name
  principal     = "elasticloadbalancing.amazonaws.com"
  source_arn    = aws_lb_target_group.echo_backend.arn
}

resource "aws_lb_target_group" "echo_backend" {
  # AWS 하드 제한: 32자. 지금 name_prefix 기준으론 딱 32자로 아슬아슬하게
  # 통과하지만(다른 name_prefix 길이에서 깨질 수 있어) 여기도 동일하게 절삭 적용.
  name        = trimsuffix(substr("${local.name_prefix}-echo-backend-tg", 0, 32), "-")
  target_type = "lambda"

  # Lambda 타겟은 health check도 Lambda 호출로 이뤄짐. Lambda 타겟은 protocol/port를
  # 지정하면 안 되고(지정 시 경고, 향후 버전엔 에러), interval도 timeout보다 커야
  # 합니다(둘 다 명시 안 하면 프로바이더 기본값끼리 충돌해서 "interval must be
  # greater than timeout" 에러가 남 - 실제로 첫 apply에서 겪은 에러).
  health_check {
    enabled  = true
    interval = 35 # Lambda 타겟의 권장/기본 주기
    timeout  = 29 # interval보다 반드시 작아야 함
    matcher  = "200"
  }
}

resource "aws_lb_target_group_attachment" "echo_backend" {
  target_group_arn = aws_lb_target_group.echo_backend.arn
  target_id        = aws_lambda_function.alb_echo_target.arn

  depends_on = [aws_lambda_permission.allow_alb_invoke]
}

output "internal_mtls_alb_dns_name" {
  value = aws_lb.internal_mtls.dns_name
}

# =============================================================================
# HR 웹앱 target group + host-header 리스너 규칙
# =============================================================================
# ALB Controller를 새 ALB를 만드는 용도(k8s Ingress)로는 안 쓰고, 이 ALB의
# target group에 Pod IP를 자동 동기화하는 TargetGroupBinding CRD 용도로만 쓴다
# (인터넷 노출 ALB를 새로 만들면 Pomerium/mTLS를 우회하는 경로가 생기기 때문 -
# hr-service/app/auth.py가 X-Pomerium-Claim-Email 헤더를 서명 검증 없이 그대로
# 신뢰하므로, 이 헤더가 Pomerium을 반드시 거쳐야만 실리는 게 보장돼야 한다).
# target_type=ip라 vpc_id가 필수이고, 실제 Pod IP 등록은 k8s TargetGroupBinding이
# 담당한다(이 tf는 target group "그릇"만 만든다).
resource "aws_lb_target_group" "employee_service" {
  name        = trimsuffix(substr("${local.name_prefix}-employee-svc-tg", 0, 32), "-")
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path    = "/healthz"
    matcher = "200"
  }
}

resource "aws_lb_target_group" "hr_service" {
  name        = trimsuffix(substr("${local.name_prefix}-hr-svc-tg", 0, 32), "-")
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path    = "/healthz"
    matcher = "200"
  }
}

resource "aws_lb_target_group" "hr_frontend" {
  name        = trimsuffix(substr("${local.name_prefix}-hr-frontend-tg", 0, 32), "-")
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.main.id

  health_check {
    path    = "/"
    matcher = "200"
  }
}

# Pomerium(Envoy)은 업스트림으로 보낼 때 Host 헤더를 원본(employee/hr.company.com)이
# 아니라 자기 `to:` 주소(이 ALB DNS 이름)로 덮어쓰므로, host_header 조건으로는
# 라우팅할 수 없다 - 대신 Pomerium이 항상 넣어주는 X-Forwarded-Host 헤더
# (원본 Host 보존)를 기준으로 라우팅한다. 경로 규칙이 catch-all "/*"보다
# 먼저 평가되도록 priority를 더 낮게(=우선순위 높게) 준다.
resource "aws_lb_listener_rule" "employee_api" {
  listener_arn = aws_lb_listener.internal_mtls_https.arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.employee_service.arn
  }

  condition {
    http_header {
      http_header_name = "X-Forwarded-Host"
      values            = ["employee.company.com"]
    }
  }
  condition {
    path_pattern { values = ["/api/employee*"] }
  }
}

resource "aws_lb_listener_rule" "employee_frontend" {
  listener_arn = aws_lb_listener.internal_mtls_https.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hr_frontend.arn
  }

  condition {
    http_header {
      http_header_name = "X-Forwarded-Host"
      values            = ["employee.company.com"]
    }
  }
}

resource "aws_lb_listener_rule" "hr_api" {
  listener_arn = aws_lb_listener.internal_mtls_https.arn
  priority     = 11

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hr_service.arn
  }

  condition {
    http_header {
      http_header_name = "X-Forwarded-Host"
      values            = ["hr.company.com"]
    }
  }
  condition {
    path_pattern { values = ["/api/hr*"] }
  }
}

resource "aws_lb_listener_rule" "hr_frontend" {
  listener_arn = aws_lb_listener.internal_mtls_https.arn
  priority     = 21

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hr_frontend.arn
  }

  condition {
    http_header {
      http_header_name = "X-Forwarded-Host"
      values            = ["hr.company.com"]
    }
  }
}
