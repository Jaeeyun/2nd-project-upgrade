#!/usr/bin/env bash
# EC2 첫 부팅 시 자동 실행. 이 인스턴스는 SSH가 없으므로(ADR-002), 이후 모든 확인은
# SSM Session Manager로 한다.
set -euo pipefail

REGION="${region}"
NAME_PREFIX="${name_prefix}"
REALM_NAME="${realm_name}"
DEV_GENERAL_ROLE_ARN="${dev_general_role_arn}"
DEV_LEAD_ROLE_ARN="${dev_lead_role_arn}"
DEV_HR_BACKEND_ROLE_ARN="${dev_hr_backend_role_arn}"
DB_GENERAL_ROLE_ARN="${db_general_role_arn}"
DB_LEAD_ROLE_ARN="${db_lead_role_arn}"
OPS_GENERAL_ROLE_ARN="${ops_general_role_arn}"
OPS_LEAD_ROLE_ARN="${ops_lead_role_arn}"
SECURITY_AUDITOR_ROLE_ARN="${security_auditor_role_arn}"
SAML_PROVIDER_ARN="${saml_provider_arn}"
ECR_REPOSITORY_URL="${ecr_repository_url}"
ALB_DNS_NAME="${alb_dns_name}"

# ---------- 1. Docker 설치 (Amazon Linux 2023) ----------
# dnf/yum 자체는 인터넷이 아니라 AL2023 리포(S3 기반)를 쓰므로 14-keycloak-vpc-endpoints.tf의
# S3 Gateway 엔드포인트만으로 동작한다 - NAT/IGW 경로 필요 없음.
dnf update -y
dnf install -y docker
systemctl enable --now docker

# ---------- 2. 내 private IP 확인 (SAN 인증서에 넣기 위함) ----------
# 이 인스턴스는 프라이빗 서브넷이라 public-ipv4/public-hostname 메타데이터
# 자체가 없다(조회하면 빈 문자열) - 더 이상 안 쓴다. 브라우저가 실제로 보는
# 주소는 앞단 ALB(ALB_DNS_NAME)이고, 그건 ALB 자체가 별도 인증서로 처리하므로
# (11-keycloak.tf의 aws_acm_certificate.keycloak_alb) 이 컨테이너 인증서
# SAN에는 안 넣어도 된다 - ALB→인스턴스 구간은 opportunistic TLS라 호스트명
# 검증을 안 한다.
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
MY_PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)

# ---------- 3. 자체서명 TLS 인증서 (SAN 필수) ----------
# Go(Pomerium이 이걸로 만들어짐)는 1.15부터 인증서에 SAN(Subject Alternative
# Name)이 없으면 CN만으로는 인증서를 인정하지 않는다("x509: certificate
# relies on legacy Common Name field"로 거부) - Pomerium이 여전히 admin
# API 등은 private IP로 직접 호출하므로(pomerium-bootstrap.sh.tpl의
# KEYCLOAK_PRIVATE_IP) 그 경로의 호스트명 검증을 통과하려면 private IP는
# SAN에 남겨둬야 한다. ALB DNS 이름도 추가해서 Terraform이 SAML descriptor를
# 조회할 때(data.http.keycloak_saml_metadata) ALB를 거치더라도 문제없게 한다.
mkdir -p /opt/keycloak/certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 30 -nodes \
  -keyout /opt/keycloak/certs/key.pem \
  -out /opt/keycloak/certs/cert.pem \
  -subj "/CN=keycloak.internal.local" \
  -addext "subjectAltName=DNS:keycloak.internal.local,DNS:$${ALB_DNS_NAME},IP:$${MY_PRIVATE_IP}"

# openssl이 만든 키는 기본 600(root 전용)인데 Keycloak 컨테이너는 non-root로
# 실행되어 못 읽는 문제가 실전 PoC에서 확인됨 -> 644로 완화
chmod 644 /opt/keycloak/certs/key.pem
chmod 644 /opt/keycloak/certs/cert.pem

# ---------- 4. admin / 테스트유저 비밀번호를 SSM Parameter Store(SecureString)에 저장 ----------
ADMIN_PASSWORD=$(openssl rand -base64 24)
aws ssm put-parameter \
  --name "/keycloak/$${NAME_PREFIX}/admin-password" \
  --value "$ADMIN_PASSWORD" \
  --type "SecureString" \
  --overwrite \
  --region "$REGION"

TEST_USER_PASSWORD='${test_user_password}'

# ---------- 5. Keycloak 컨테이너 실행 ----------
# 예전엔 quay.io(외부/타사 레지스트리)에서 직접 pull했다 - 이제는 프라이빗
# 서브넷이라 그 경로 자체가 없고(NAT 없음), 설령 있었더라도 검증 안 된
# 외부 이미지를 매 배포마다 그대로 받는 건 공급망 보안 관점에서 좋지 않다.
# 대신 scripts/mirror-keycloak-image-to-ecr.sh로 사람이 미리(배포 전 1회,
# 인터넷 되는 자기 컴퓨터에서) 이 계정의 ECR로 이미지를 미러링해두고,
# 여기서는 ECR API/DKR VPC 엔드포인트로만 받는다(14-keycloak-vpc-endpoints.tf).
aws ecr get-login-password --region "$REGION" | \
  docker login --username AWS --password-stdin "$ECR_REPOSITORY_URL"

docker run -d \
  --name keycloak \
  --restart unless-stopped \
  -p 443:8443 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
  -e KC_HTTPS_CERTIFICATE_FILE=/etc/keycloak/certs/cert.pem \
  -e KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/keycloak/certs/key.pem \
  -e KC_HOSTNAME_STRICT=false \
  -v /opt/keycloak/certs:/etc/keycloak/certs:ro \
  "$ECR_REPOSITORY_URL:26.7.0" \
  start-dev

echo "Keycloak 기동 대기 중..."
for i in $(seq 1 60); do
  if docker exec keycloak curl -sf http://localhost:8080/realms/master > /dev/null 2>&1; then
    echo "Keycloak 준비 완료"
    break
  fi
  sleep 5
done

# docker exec는 기본적으로 컨테이너 프로세스의 stdin을 연결하지 않으므로,
# 아래에서 -f - <<'HEREDOC'로 JSON을 넘기려면 -i(stdin 연결)가 반드시 필요하다.
KC="docker exec -i keycloak /opt/keycloak/bin/kcadm.sh"

# ---------- 6. kcadm 로그인 ----------
$KC config credentials \
  --server http://localhost:8080 --realm master --user admin --password "$ADMIN_PASSWORD"

# ---------- 7. Realm 생성 + MFA(OTP)/브루트포스 정책 ----------
$KC create realms -s realm="$REALM_NAME" -s enabled=true

$KC update realms/"$REALM_NAME" \
  -s otpPolicyType=totp -s otpPolicyAlgorithm=HmacSHA1 -s otpPolicyDigits=6 \
  -s otpPolicyInitialCounter=0 -s otpPolicyPeriod=30 \
  -s bruteForceProtected=true -s failureFactor=5 -s waitIncrementSeconds=60 \
  -s quickLoginCheckMilliSeconds=1000 -s minimumQuickLoginWaitSeconds=60 \
  -s maxFailureWaitSeconds=900 -s maxDeltaTimeSeconds=43200

# ---------- 8. User Profile: Unmanaged Attributes 활성화 ----------
$KC update users/profile -r "$REALM_NAME" -f - <<'PROFILE'
{
  "attributes": [
    {"name": "username"},
    {"name": "email"}
  ],
  "unmanagedAttributePolicy": "ENABLED"
}
PROFILE

# ---------- 9. SAML 클라이언트 생성 ----------
$KC create clients -r "$REALM_NAME" -f - <<'CLIENT'
{
  "clientId": "urn:amazon:webservices",
  "name": "AWS Console/CLI (SAML)",
  "protocol": "saml",
  "enabled": true,
  "fullScopeAllowed": false,
  "attributes": {
    "saml_assertion_consumer_url_post": "https://signin.aws.amazon.com/saml",
    "saml_name_id_format": "email",
    "saml.server.signature": "true",
    "saml.assertion.signature": "true",
    "saml.authnstatement": "true",
    "saml_force_post_binding": "true",
    "saml_idp_initiated_sso_url_name": "aws"
  }
}
CLIENT

CID=$($KC get clients -r "$REALM_NAME" -q clientId=urn:amazon:webservices --fields id --format csv --noquotes | tail -1 | tr -d '\r')

# ---------- 10. 프로토콜 매퍼 3종 ----------
$KC create clients/"$CID"/protocol-mappers/models -r "$REALM_NAME" -f - <<'M1'
{"name":"aws-role-list","protocol":"saml","protocolMapper":"saml-user-attribute-mapper",
 "config":{"attribute.name":"https://aws.amazon.com/SAML/Attributes/Role","attribute.nameformat":"Basic","user.attribute":"aws_role_arn"}}
M1

$KC create clients/"$CID"/protocol-mappers/models -r "$REALM_NAME" -f - <<'M2'
{"name":"aws-role-session-name","protocol":"saml","protocolMapper":"saml-user-property-mapper",
 "config":{"attribute.name":"https://aws.amazon.com/SAML/Attributes/RoleSessionName","attribute.nameformat":"Basic","user.attribute":"username"}}
M2

$KC create clients/"$CID"/protocol-mappers/models -r "$REALM_NAME" -f - <<'M3'
{"name":"aws-session-duration","protocol":"saml","protocolMapper":"saml-hardcode-attribute-mapper",
 "config":{"attribute.name":"https://aws.amazon.com/SAML/Attributes/SessionDuration","attribute.nameformat":"Basic","attribute.value":"3600"}}
M3

# ---------- 11. 그룹 8개 + 그룹당 테스트 유저 1명 ----------
create_role_group() {
  local group_name="$1"
  local role_arn="$2"

  $KC create groups -r "$REALM_NAME" -f - <<GRPEOF
{"name": "$group_name", "attributes": {"aws_role_arn": ["$role_arn,$SAML_PROVIDER_ARN"]}}
GRPEOF
}

create_role_group "dev-general"       "$${DEV_GENERAL_ROLE_ARN}"
create_role_group "dev-lead"          "$${DEV_LEAD_ROLE_ARN}"
create_role_group "dev-hr-backend"    "$${DEV_HR_BACKEND_ROLE_ARN}"
create_role_group "db-general"        "$${DB_GENERAL_ROLE_ARN}"
create_role_group "db-lead"           "$${DB_LEAD_ROLE_ARN}"
create_role_group "ops-general"       "$${OPS_GENERAL_ROLE_ARN}"
create_role_group "ops-lead"          "$${OPS_LEAD_ROLE_ARN}"
create_role_group "security-auditor" "$${SECURITY_AUDITOR_ROLE_ARN}"

create_test_user_in_group() {
  local username="$1"
  local group_name="$2"

  $KC create users -r "$REALM_NAME" -f - <<USREOF
{
  "username": "$username",
  "enabled": true,
  "email": "$${username}@example.com",
  "emailVerified": true,
  "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP"]
}
USREOF

  local group_id
  group_id=$($KC get groups -r "$REALM_NAME" -q search="$group_name" --fields id,name --format csv --noquotes \
    | grep ",$group_name$" | cut -d, -f1)
  local user_id
  user_id=$($KC get users -r "$REALM_NAME" -q username="$username" --fields id --format csv --noquotes | tail -1)

  $KC update "users/$${user_id}/groups/$${group_id}" -r "$REALM_NAME" -f - <<< '{}'
  $KC set-password -r "$REALM_NAME" --username "$username" --new-password "$TEST_USER_PASSWORD" --temporary
}

create_test_user_in_group "test-dev-general"      "dev-general"
create_test_user_in_group "test-dev-lead"          "dev-lead"
create_test_user_in_group "test-dev-hr-backend"    "dev-hr-backend"
create_test_user_in_group "test-db-general"        "db-general"
create_test_user_in_group "test-db-lead"           "db-lead"
create_test_user_in_group "test-ops-general"       "ops-general"
create_test_user_in_group "test-ops-lead"          "ops-lead"
create_test_user_in_group "test-security-auditor" "security-auditor"

# ---------- 12. HR 웹앱 로그인 전용 계정 4명 (AWS 인프라 접근 무관, SAML Role 그룹 미가입) ----------
# 위 8개는 AWS 콘솔/kubectl용 SAML Role 그룹 계정이고, 이 4명은 Pomerium OIDC로
# HR 웹앱(employee/hr 사이트)에만 로그인한다. is_hr 여부는 Keycloak이 아니라
# RDS employees.is_hr 컬럼이 판단하므로 그룹 가입이 필요 없다.
create_hr_app_user() {
  local email="$1"

  $KC create users -r "$REALM_NAME" -f - <<USREOF
{
  "username": "$email",
  "enabled": true,
  "email": "$email",
  "emailVerified": true,
  "requiredActions": ["UPDATE_PASSWORD", "CONFIGURE_TOTP"]
}
USREOF

  $KC set-password -r "$REALM_NAME" --username "$email" --new-password "$TEST_USER_PASSWORD" --temporary
}

create_hr_app_user "chulsoo.kim@company.com"
create_hr_app_user "younghee.lee@company.com"
create_hr_app_user "gildong.hong@company.com"
create_hr_app_user "minsu.park@company.com"

# ---------- 13. Scene 10(세션 강제 종료) 데모 전용 계정 ----------
# 위 8개 SAML Role 계정은 각자 다른 씬(3, 12 등)에서 실제로 쓰이고 있어서,
# Scene 10 촬영 때마다 강제 로그아웃시키면 다른 씬 준비 상태가 깨진다.
# 그래서 dev-general 권한만 가진 전용 계정을 하나 더 둔다 - 촬영 중 반복
# 로그인/강제종료를 여러 번 해도 다른 데모 계정에 영향이 없다.
#
# TOTP를 요구하지 않는 이유: 나머지 8개 계정과 달리 이 계정은 매 촬영마다
# 새로 로그인해야 하는데, CONFIGURE_TOTP가 걸려있으면 매번 OTP 앱 등록
# 화면이 끼어들어 반복 촬영(멱등성 요구사항)에 안 맞는다. 권한 범위가
# dev-general(최소 수준)으로 좁아서 보안 완화의 실질적 위험도 적다.
$KC create users -r "$REALM_NAME" -f - <<USREOF
{
  "username": "test-session-revoke-demo",
  "enabled": true,
  "email": "test-session-revoke-demo@example.com",
  "emailVerified": true,
  "requiredActions": []
}
USREOF
SESSION_DEMO_GROUP_ID=$($KC get groups -r "$REALM_NAME" -q search="dev-general" --fields id,name --format csv --noquotes \
  | grep ",dev-general$" | cut -d, -f1)
SESSION_DEMO_USER_ID=$($KC get users -r "$REALM_NAME" -q username="test-session-revoke-demo" --fields id --format csv --noquotes | tail -1)
$KC update "users/$${SESSION_DEMO_USER_ID}/groups/$${SESSION_DEMO_GROUP_ID}" -r "$REALM_NAME" -f - <<< '{}'
$KC set-password -r "$REALM_NAME" --username "test-session-revoke-demo" --new-password "$TEST_USER_PASSWORD" --temporary=false

echo "Keycloak 부트스트랩 완료. admin 비밀번호: SSM Parameter /keycloak/$${NAME_PREFIX}/admin-password"
echo "테스트 계정 8개(Role별 1명씩) 전부 동일한 임시 비밀번호로 생성됨."
