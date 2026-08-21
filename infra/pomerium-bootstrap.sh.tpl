#!/usr/bin/env bash
# Pomerium PoC 부트스트랩. SSH 없음(ADR-002) - 확인은 SSM으로.
set -euo pipefail

REGION="${region}"
NAME_PREFIX="${name_prefix}"
# Keycloak이 프라이빗 서브넷에 있어서(11-keycloak.tf) 서버간 호출(Admin API,
# 토큰 교환)은 이 private IP로만 가능하다 - 퍼블릭 경로 자체가 없음.
KEYCLOAK_PRIVATE_IP="${keycloak_private_ip}"
# idp_provider_url(OIDC discovery/token + 최종 사용자 브라우저 리다이렉트)은
# Keycloak 앞단 ALB의 DNS 이름을 쓴다 - 11-keycloak.tf의 aws_lb.keycloak 참고.
KEYCLOAK_ENDPOINT="${keycloak_endpoint}"
REALM_NAME="${realm_name}"

# ---------- 1. Docker 설치 ----------
dnf update -y
dnf install -y docker openssl
systemctl enable --now docker

# ---------- 2. 내 퍼블릭 IP ----------
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
MY_PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)

# ---------- 3. Keycloak 준비 대기 (private IP로) ----------
echo "Keycloak 응답 대기 중..."
for i in $(seq 1 90); do
  if curl -sk --max-time 5 "https://$${KEYCLOAK_PRIVATE_IP}/realms/$${REALM_NAME}" > /dev/null 2>&1; then
    echo "Keycloak 준비 완료"
    break
  fi
  echo "  아직 준비 안 됨, 10초 후 재시도... ($i/90)"
  sleep 10
done

# ---------- 4. Keycloak의 자체서명 인증서를 로컬 파일로 저장 ----------
# Go는 SAN 없는 인증서를 거부(Keycloak엔 SAN 추가함). 자체서명이라 시스템 기본
# 신뢰 루트엔 없어서, config.yaml의 certificate_authority_file에 직접 지정한다.
mkdir -p /etc/pki/ca-trust/source/anchors
echo | openssl s_client -connect "$${KEYCLOAK_PRIVATE_IP}:443" -servername "$${KEYCLOAK_PRIVATE_IP}" 2>/dev/null \
  | openssl x509 > /etc/pki/ca-trust/source/anchors/keycloak.pem
update-ca-trust

# ---------- 5. 우리 mTLS CA(내부 ALB 서버 인증서 서명용)도 저장 ----------
cat > /etc/pki/ca-trust/source/anchors/internal-ca.pem <<'CAEOF'
${ca_cert_pem}
CAEOF
update-ca-trust

# ---------- 6. Keycloak admin 비밀번호 조회 ----------
ADMIN_PASSWORD=$(aws ssm get-parameter --name "/keycloak/$${NAME_PREFIX}/admin-password" \
  --with-decryption --query Parameter.Value --output text --region "$${REGION}")

# ---------- 7. Admin 토큰 발급 (private IP + -k, 재시도 포함) ----------
# ADMIN_PASSWORD는 openssl rand -base64라 "+"가 나올 수 있는데 curl -d는 URL
# 인코딩을 안 해서(+가 공백으로 해석됨) 간헐적으로 invalid_grant가 났었다 -
# password만 --data-urlencode로 바꿔 실제 값 그대로 인코딩한다.
ADMIN_TOKEN=""
for i in $(seq 1 12); do
  ADMIN_TOKEN=$(curl -sfk --max-time 10 -X POST "https://$${KEYCLOAK_PRIVATE_IP}/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" -d "grant_type=password" \
    -d "username=admin" --data-urlencode "password=$${ADMIN_PASSWORD}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")
  if [ -n "$${ADMIN_TOKEN}" ]; then
    echo "관리자 토큰 발급 성공"
    break
  fi
  echo "  관리자 API 아직 준비 안 됨, 5초 후 재시도... ($i/12)"
  sleep 5
done

if [ -z "$${ADMIN_TOKEN}" ]; then
  echo "관리자 토큰 발급 최종 실패 - Keycloak 상태를 SSM으로 직접 확인하세요." >&2
  exit 1
fi

# ---------- 8. Pomerium용 OIDC 클라이언트 등록 (없으면 생성, private IP로) ----------
EXISTING_CLIENT=$(curl -sfk -H "Authorization: Bearer $${ADMIN_TOKEN}" \
  "https://$${KEYCLOAK_PRIVATE_IP}/admin/realms/$${REALM_NAME}/clients?clientId=pomerium" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')")

if [ -z "$${EXISTING_CLIENT}" ]; then
  echo "Pomerium OIDC 클라이언트 생성 중..."
  curl -sfk -X POST "https://$${KEYCLOAK_PRIVATE_IP}/admin/realms/$${REALM_NAME}/clients" \
    -H "Authorization: Bearer $${ADMIN_TOKEN}" -H "Content-Type: application/json" \
    -d "{
      \"clientId\": \"pomerium\",
      \"protocol\": \"openid-connect\",
      \"publicClient\": false,
      \"standardFlowEnabled\": true,
      \"directAccessGrantsEnabled\": false,
      \"redirectUris\": [\"https://$${MY_PUBLIC_IP}/oauth2/callback\"],
      \"webOrigins\": [\"https://$${MY_PUBLIC_IP}\"]
    }"
  CLIENT_UUID=$(curl -sfk -H "Authorization: Bearer $${ADMIN_TOKEN}" \
    "https://$${KEYCLOAK_PRIVATE_IP}/admin/realms/$${REALM_NAME}/clients?clientId=pomerium" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
else
  CLIENT_UUID="$${EXISTING_CLIENT}"
  # Pomerium만 재생성돼도 IP가 바뀌는데 재사용 시 redirectUris를 안 고치면 옛
  # IP로 남아 "Invalid redirect_uri"로 막힌다 - 갱신해서 다시 저장한다.
  curl -sfk -H "Authorization: Bearer $${ADMIN_TOKEN}" \
    "https://$${KEYCLOAK_PRIVATE_IP}/admin/realms/$${REALM_NAME}/clients/$${CLIENT_UUID}" \
    | python3 -c "
import sys, json
c = json.load(sys.stdin)
c['redirectUris'] = ['https://$${MY_PUBLIC_IP}/oauth2/callback']
c['webOrigins'] = ['https://$${MY_PUBLIC_IP}']
print(json.dumps(c))" > /tmp/pomerium_client.json
  curl -sfk -X PUT "https://$${KEYCLOAK_PRIVATE_IP}/admin/realms/$${REALM_NAME}/clients/$${CLIENT_UUID}" \
    -H "Authorization: Bearer $${ADMIN_TOKEN}" -H "Content-Type: application/json" \
    --data @/tmp/pomerium_client.json
fi

CLIENT_SECRET=$(curl -sfk -H "Authorization: Bearer $${ADMIN_TOKEN}" \
  "https://$${KEYCLOAK_PRIVATE_IP}/admin/realms/$${REALM_NAME}/clients/$${CLIENT_UUID}/client-secret" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['value'])")

# ---------- 9. Pomerium 자체 TLS 인증서(브라우저용) ----------
# employee/hr.company.com도 SAN에 추가 - 사용자 hosts 파일로 이 IP에 매핑됨.
mkdir -p /opt/pomerium/certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 30 -nodes \
  -keyout /opt/pomerium/certs/pomerium-key.pem \
  -out /opt/pomerium/certs/pomerium-cert.pem \
  -subj "/CN=$${MY_PUBLIC_IP}" \
  -addext "subjectAltName=IP:$${MY_PUBLIC_IP},DNS:employee.company.com,DNS:hr.company.com"
chmod 644 /opt/pomerium/certs/pomerium-key.pem /opt/pomerium/certs/pomerium-cert.pem

# ---------- 10. mTLS 클라이언트 인증서(내부 ALB용, Terraform이 생성해서 넘겨준 것) ----------
cat > /opt/pomerium/certs/client-cert.pem <<'CERTEOF'
${client_cert_pem}
CERTEOF
cat > /opt/pomerium/certs/client-key.pem <<'KEYEOF'
${client_key_pem}
KEYEOF
chmod 644 /opt/pomerium/certs/client-cert.pem /opt/pomerium/certs/client-key.pem

# Keycloak CA도 컨테이너 마운트 경로로 복사(11단계 certificate_authority_file용).
cp /etc/pki/ca-trust/source/anchors/keycloak.pem /opt/pomerium/certs/keycloak-ca.pem
chmod 644 /opt/pomerium/certs/keycloak-ca.pem

# ---------- 11. Pomerium 설정 파일 ----------
COOKIE_SECRET=$(openssl rand -base64 32)
SHARED_SECRET=$(openssl rand -base64 32)
# 라우트 3개가 공통으로 쓰는 mTLS/인가 설정을 변수 하나로 묶어 중복을 줄인다.
# pass_identity_headers(기본 false)를 켜야 X-Pomerium-Claim-Email이 앱으로
# 전달된다(is_hr 판정은 앱이 RDS 기준으로 직접 하므로 여기선 안 가림).
# ⚠️ X-Pomerium-Claim-Email은 클라이언트가 브라우저에서 직접 조작해 보낼 수
# 있는 평문 헤더라(ModHeader 등으로 남의 이메일을 위장 가능) 신뢰하지 않는다.
# Envoy route의 remove_request_headers로는 막을 수 없다(ext_authz가 붙인
# 정상 헤더까지 같은 이름이라 함께 지워짐 - TROUBLESHOOTING.md 참고). 이
# 헤더는 그대로 두되(Pomerium이 계속 정확한 값으로 갱신함), 앱 쪽(auth.py)이
# 위조 불가능한 서명된 x-pomerium-jwt-assertion을 JWKS로 검증해서 이메일을
# 뽑는 쪽을 신뢰의 근거로 쓴다.
ROUTE_COMMON="    tls_client_cert_file: /etc/pomerium/certs/client-cert.pem
    tls_client_key_file: /etc/pomerium/certs/client-key.pem
    tls_skip_verify: true
    allow_public_unauthenticated_access: false
    allow_any_authenticated_user: true
    pass_identity_headers: true"

cat > /opt/pomerium/config.yaml <<CONFEOF
address: :443
insecure_server: false
certificate_file: /etc/pomerium/certs/pomerium-cert.pem
certificate_key_file: /etc/pomerium/certs/pomerium-key.pem

cookie_secret: $${COOKIE_SECRET}
shared_secret: $${SHARED_SECRET}

# self-hosted 모드로 쓰려면 이 authenticate 기능도 나 자신이 처리한다고 명시.
authenticate_service_url: https://$${MY_PUBLIC_IP}

idp_provider: oidc
idp_provider_url: https://$${KEYCLOAK_ENDPOINT}/realms/$${REALM_NAME}
idp_client_id: pomerium
idp_client_secret: $${CLIENT_SECRET}
idp_scopes: [openid, profile, email]
# idp_provider_ca는 이 Pomerium 버전(0.33.0)엔 없는 옵션이라 조용히 무시됐다 -
# 유효한 키인 certificate_authority_file로 Keycloak CA를 신뢰시킨다.
certificate_authority_file: /etc/pomerium/certs/keycloak-ca.pem

routes:
  - from: https://$${MY_PUBLIC_IP}
    to: https://${alb_dns_name}
$${ROUTE_COMMON}
  - from: https://employee.company.com
    to: https://${alb_dns_name}
$${ROUTE_COMMON}
  - from: https://hr.company.com
    to: https://${alb_dns_name}
$${ROUTE_COMMON}
CONFEOF

echo "Pomerium 설정 완료. 컨테이너 기동..."

# ---------- 12. Pomerium 컨테이너 기동 ----------
# cr.pomerium.com은 이 환경에서 DNS 조회가 안 돼 Docker Hub 태그로 원상복구.
docker run -d \
  --name pomerium \
  --restart unless-stopped \
  -p 443:443 \
  -v /opt/pomerium/config.yaml:/pomerium/config.yaml:ro \
  -v /opt/pomerium/certs:/etc/pomerium/certs:ro \
  pomerium/pomerium:latest

echo "Pomerium 부트스트랩 완료. https://$${MY_PUBLIC_IP}/ (또는 employee/hr.company.com)"
