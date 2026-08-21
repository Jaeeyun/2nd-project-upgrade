#!/usr/bin/env bash
# =============================================================================
# Scene 10: (Custom Action) Security Hub 1-Click → 긴급 세션 강제 종료 검증
# =============================================================================
# test-session-revoke-demo(43-demo-scenario-resources.tf 근처, 실제로는
# keycloak-bootstrap.sh.tpl에서 생성되는 전용 데모 계정) 대상으로
# scripts/session-revoke.py Lambda를 수동 테스트 이벤트 경로({"username":..})로
# 직접 호출한다 - 실제 Security Hub Custom Action 클릭과 최종 동작은 동일하다.
# 이 계정은 dev-general 권한만 가진 격리된 계정이라, 다른 씬에서 쓰는
# 계정(test-ops-lead 등)에는 영향이 없다.
# 멱등: 8개 Role에 붙는 Deny 인라인 정책은 검증 후 스스로 지운다(실제
# 촬영에서는 "진짜로 세션이 끊기는지"를 보여주는 게 목적이라 남겨둘 수도
# 있지만, 반복 재검증에는 방해가 되므로 스크립트에서는 정리한다).
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 10 "Security Hub 1-Click → 긴급 세션 강제 종료 검증" \
  "위협 상황 가정: 긴급 세션 종료 Lambda 수동 테스트 이벤트로 직접 호출" \
  "8개 Role에 세션 차단(Deny) 인라인 정책 부착 확인" \
  "Keycloak SSO 세션 강제 로그아웃 확인 및 정리"

USERNAME="test-session-revoke-demo"
LAMBDA_NAME="demo-project-dev-session-revoke"
PASS=1

step 1 "긴급 세션 종료 Lambda 직접 호출"
threat "위협 계정($USERNAME)의 모든 세션을 즉시 강제 종료합니다"
INVOKE_OUT=$(aws lambda invoke --function-name "$LAMBDA_NAME" \
  --payload "$(printf '{"username":"%s"}' "$USERNAME")" \
  --cli-binary-format raw-in-base64-out /tmp/scene10-out.json 2>&1)
echo "$INVOKE_OUT"
cat /tmp/scene10-out.json 2>/dev/null; echo

REVOKED_ROLES=$(python3 -c "import json; d=json.load(open('/tmp/scene10-out.json')); print(len(d.get('revoked_roles',[])))" 2>/dev/null || echo 0)
KC_LOGGED_OUT=$(python3 -c "import json; print(json.load(open('/tmp/scene10-out.json')).get('keycloak_logged_out'))" 2>/dev/null || echo "unknown")

step 2 "AWS 세션 차단(Deny 인라인 정책) 확인"
if [ "$REVOKED_ROLES" -ge "1" ] 2>/dev/null; then
  ok "$REVOKED_ROLES 개 Role에 차단 정책이 붙음"
  # 실제로 정책 내용이 이 사용자만 겨냥하는지 하나 골라 확인
  SAMPLE_ROLE="demo-project-dev-dev-general"
  POLICY=$(aws iam get-role-policy --role-name "$SAMPLE_ROLE" --policy-name "revoke-session-$USERNAME" --query 'PolicyDocument' --output json 2>&1)
  if echo "$POLICY" | grep -q "$USERNAME"; then
    ok "정책이 정확히 $USERNAME 세션만 겨냥함(aws:userid 조건 확인)"
  else
    fail "정책 내용에서 대상 사용자를 확인 못 함"
    PASS=0
  fi
else
  fail "차단 정책이 붙은 Role이 0개"
  PASS=0
fi

step 3 "Keycloak SSO 세션 강제 로그아웃 확인 및 정리"
if [ "$KC_LOGGED_OUT" = "True" ]; then
  ok "Keycloak 세션 로그아웃 성공"
else
  fail "Keycloak 로그아웃 실패 또는 확인 불가 (응답: $KC_LOGGED_OUT)"
  PASS=0
fi

progress "정리: 데모용 차단 정책 제거(반복 검증을 위해)"
for role in demo-project-dev-db-general demo-project-dev-db-lead demo-project-dev-dev-general \
  demo-project-dev-dev-hr-backend demo-project-dev-dev-lead demo-project-dev-ops-general \
  demo-project-dev-ops-lead demo-project-dev-security-auditor; do
  aws iam delete-role-policy --role-name "$role" --policy-name "revoke-session-$USERNAME" >/dev/null 2>&1 || true
done

rm -f /tmp/scene10-out.json

if [ "$PASS" = "1" ]; then
  result_box PASSED "위협 계정 세션 즉시 강제 종료 확인"
  scene_report 10 "Security Hub 1-Click 긴급 세션 강제 종료" PASSED "aws lambda invoke demo-project-dev-session-revoke"
else
  result_box FAILED "세션 차단 또는 로그아웃 확인 실패"
  scene_report 10 "Security Hub 1-Click 긴급 세션 강제 종료" FAILED "aws lambda invoke demo-project-dev-session-revoke"
  exit 1
fi
