# =============================================================================
# 로그인 컨텍스트 게이트 정책 (ADR-022)
# =============================================================================
# Keycloak Authenticator SPI(infra/opa-keycloak-spi)가 브라우저 로그인 플로우
# 중간에 이 정책을 호출한다 - 8개 SAML Role 그룹 계정(AWS 인프라 접근용)에만
# 적용되고, HR 웹앱 전용 계정(keycloak-bootstrap.sh.tpl 12번 섹션)에는 붙지
# 않는다(그 계정들은 Pomerium 뒤 HR 앱 접근이 목적이라 이 정책 대상이 아님).
#
# 호출 계약(SPI → OPA):
#   POST /v1/data/login_context/allow
#   { "input": {
#       "username": "gildong",
#       "source_ip": "203.0.113.10",
#       "group": "dev-general",
#       "mfa_configured": true
#   }}
# 응답: {"result": true|false}
#
# ⚠️ mfa_configured는 "이 사용자가 OTP를 등록해뒀는가"이지 "이번 로그인에서
# 실제로 OTP를 입력해서 통과했는가"와 완전히 같지 않다 - SPI를 브라우저 플로우의
# OTP 실행 단계 "뒤"에 배치해서 여기까지 도달했다는 것 자체가 OTP를 통과했다는
# 뜻이 되도록 흐름을 짜는 게 전제다(opa-keycloak-spi/README.md 참고). SPI가
# 세션에서 "이번 로그인에 실제로 OTP를 썼는지"를 더 정확히 읽어오는 방법은
# [검증 필요]로 남겨둔다.
package login_context

import future.keywords.if
import future.keywords.in

default allow := false

# 8개 SAML Role 그룹 전부에 적용할 기본 허용 네트워크 대역.
# security-auditor는 12-iam-saml-roles.tf의 신뢰정책에 이미 별도 CIDR 조건이
# 있으므로(ADR-001 결정 3) 여기서 한 번 더 걸어도 중복 방어일 뿐 해가 없다.
allowed_cidrs := [
	"10.0.0.0/16", # workload VPC 내부(디버그/CI 등에서 오는 경우)
	"10.1.0.0/16", # Keycloak/Pomerium VPC 내부
	"203.0.113.0/24", # 사내 VPN 대역 - 실제 배포 시 keycloak_admin_cidr 값으로 교체
]

allow if {
	source_ip_allowed
	input.mfa_configured == true
}

source_ip_allowed if {
	some cidr in allowed_cidrs
	net.cidr_contains(cidr, input.source_ip)
}

# 왜 거부됐는지를 SPI가 로그/Slack 메시지에 그대로 쓸 수 있게 이유를 같이 반환.
# (OPA 결정 로그에도 이 값이 그대로 남아 event_id 없이도 사람이 바로 읽을 수 있음)
# 검증 완료(OPA v0.70.0, opa check + opa eval로 4개 분기 전부 기대값과 일치
# 확인 - IP만 걸림/MFA만 걸림/둘다 걸림/둘다 통과). else 체이닝 문법 포함
# 전부 정상 동작.
deny_reason := reason if {
	not source_ip_allowed
	not input.mfa_configured == true
	reason := "허용되지 않은 네트워크 대역 + MFA 미완료"
} else := reason if {
	not source_ip_allowed
	reason := "허용되지 않은 네트워크 대역"
} else := reason if {
	not input.mfa_configured == true
	reason := "MFA 미완료"
} else := "" if {
	allow
}
