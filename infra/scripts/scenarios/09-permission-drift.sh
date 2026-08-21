#!/usr/bin/env bash
# =============================================================================
# Scene 9: DB 마스킹 우회(GRANT) 감지 → Cron Lambda 자동 REVOKE 대응 검증
# =============================================================================
# db_admin(테이블 소유자급 권한)으로 employees 원본 테이블에 대한 직접 GRANT를
# 일부러 만들어(=마스킹 뷰 우회) 드리프트를 재현한 뒤, 매일 새벽 03:00에
# 도는 Lambda(scripts/rds-view-permission-check.py)를 직접 호출해서 실제로
# REVOKE되는지 확인한다.
# 멱등: 실행할 때마다 먼저 드리프트를 만들고 나서 Lambda로 되돌리므로,
# 끝나면 항상 드리프트 없는 상태로 돌아온다.
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 09 "DB 마스킹 우회(GRANT) 드리프트 탐지 → 자동 REVOKE 대응 검증" \
  "employees 원본 테이블에 직접 GRANT → 마스킹 우회 드리프트 고의 재현" \
  "권한 드리프트 점검 Lambda(cron) 직접 호출 → 드리프트 탐지" \
  "우회 권한 자동 REVOKE 및 원복 확인"

CLUSTER=$(tf_output eks_cluster_name)
KUBECONFIG_FILE=$(mktemp)
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" --kubeconfig "$KUBECONFIG_FILE" >/dev/null
K() { kubectl --kubeconfig "$KUBECONFIG_FILE" "$@"; }

RDS_HOST=$(tf_output rds_endpoint | cut -d: -f1)
POD=scene9-drift-check
PASS=1

cleanup() { K delete pod "$POD" -n default --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1; rm -f "$KUBECONFIG_FILE"; }
trap cleanup EXIT
K delete pod "$POD" -n default --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1

progress "디버그 파드 기동"
K run "$POD" -n default --image=postgres:15-alpine --restart=Never --command -- sleep 300 >/dev/null
K wait --for=condition=Ready "pod/$POD" -n default --timeout=90s >/dev/null 2>&1

psql_as_admin() {
  local sql="$1" token
  token=$(aws rds generate-db-auth-token --hostname "$RDS_HOST" --port 5432 --username db_admin --region "$AWS_REGION")
  K exec "$POD" -n default -- env PGPASSWORD="$token" PGSSLMODE=require \
    psql "host=$RDS_HOST port=5432 dbname=demodb user=db_admin" -t -c "$sql" 2>&1
}

step 1 "마스킹 우회 GRANT 드리프트 고의 재현"
threat "드리프트 재현: general_user_readonly에 employees 원본 테이블 직접 GRANT (마스킹 뷰 우회)"
psql_as_admin "GRANT SELECT ON employees TO general_user_readonly;" >/dev/null

DRIFT_BEFORE=$(psql_as_admin "SELECT count(*) FROM information_schema.role_table_grants WHERE table_name='employees' AND grantee='general_user_readonly';" | tr -d ' ')
if [ "$DRIFT_BEFORE" = "1" ]; then
  ok "드리프트(우회 권한)가 실제로 생성됨"
else
  fail "드리프트 생성 자체가 안 됨 (조회값=$DRIFT_BEFORE)"
  PASS=0
fi

step 2 "권한 드리프트 점검 Lambda 직접 호출 → 드리프트 탐지"
INVOKE_OUT=$(aws lambda invoke --function-name "demo-project-dev-rds-view-permission-check" --payload '{}' --cli-binary-format raw-in-base64-out /tmp/scene9-lambda-out.json 2>&1)
echo "$INVOKE_OUT"
cat /tmp/scene9-lambda-out.json 2>/dev/null
echo

DRIFT_COUNT=$(python3 -c "import json; print(json.load(open('/tmp/scene9-lambda-out.json')).get('drift_count', -1))" 2>/dev/null || echo -1)
if [ "$DRIFT_COUNT" -ge "1" ] 2>/dev/null; then
  ok "Lambda가 드리프트 $DRIFT_COUNT 건을 발견하고 REVOKE 실행"
else
  fail "Lambda 응답에서 drift_count>=1을 확인 못 함 (응답: $(cat /tmp/scene9-lambda-out.json 2>/dev/null))"
  PASS=0
fi

step 3 "우회 권한 자동 REVOKE 및 원복 확인"
DRIFT_AFTER=$(psql_as_admin "SELECT count(*) FROM information_schema.role_table_grants WHERE table_name='employees' AND grantee='general_user_readonly';" | tr -d ' ')
if [ "$DRIFT_AFTER" = "0" ]; then
  ok "REVOKE 확인됨 - 우회 권한 없음"
else
  fail "우회 권한이 여전히 남아있음"
  PASS=0
  psql_as_admin "REVOKE ALL ON employees FROM general_user_readonly;" >/dev/null
fi

rm -f /tmp/scene9-lambda-out.json

if [ "$PASS" = "1" ]; then
  result_box PASSED "드리프트 자동 탐지 및 REVOKE 완료"
  scene_report 9 "DB 마스킹 우회 GRANT 드리프트 자동 REVOKE" PASSED "aws lambda invoke demo-project-dev-rds-view-permission-check"
else
  result_box FAILED "드리프트 탐지 또는 REVOKE 실패"
  scene_report 9 "DB 마스킹 우회 GRANT 드리프트 자동 REVOKE" FAILED "aws lambda invoke demo-project-dev-rds-view-permission-check"
  exit 1
fi
