#!/usr/bin/env bash
# =============================================================================
# Scene 5: HR RDS PII 데이터 2중 마스킹 & IAM DB Auth 접속 검증
# =============================================================================
# RDS는 demo VPC CIDR만 허용해서(03-security.tf rds_sg) 이 스크립트를 돌리는
# 머신에서 직접 못 붙는다 - EKS 워커 노드는 같은 VPC라 접속 가능하므로,
# kubectl run으로 뜨는 임시 디버그 파드에서 psql을 실행한다(노드 Role에
# 좁게 부여한 rds-db:connect 권한을 파드가 상속 - 43-demo-scenario-resources.tf
# 참고). 파드는 매 실행 끝에 삭제한다(멱등 - 이전 실행의 잔여물이 안 남음).
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 05 "HR RDS PII 데이터 이중 마스킹 + IAM DB Auth 접속 검증" \
  "임시 디버그 파드 기동 → IAM 인증 토큰만으로 RDS 접속(고정 비밀번호 없음)" \
  "general_user_readonly로 마스킹 뷰 조회 → salary 컬럼이 NULL로 가려지는지 확인" \
  "security_auditor_readonly 접속 및 IAM DB Auth 활성화 상태까지 최종 확인"

CLUSTER=$(tf_output eks_cluster_name)
KUBECONFIG_FILE=$(mktemp)
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" --kubeconfig "$KUBECONFIG_FILE" >/dev/null
K() { kubectl --kubeconfig "$KUBECONFIG_FILE" "$@"; }

RDS_HOST=$(tf_output rds_endpoint | cut -d: -f1)
POD=scene5-pii-check
PASS=1

cleanup() { K delete pod "$POD" -n default --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1; rm -f "$KUBECONFIG_FILE"; }
trap cleanup EXIT

# --wait=false로 지우면 다음 실행이 바로 같은 이름으로 재생성을 시도하다가
# "object is being deleted" 경합이 날 수 있어, 시작 시점 정리는 완전 삭제될
# 때까지 기다린다(멱등성 - 직전 실행이 비정상 종료해 파드가 남아있어도 안전).
K delete pod "$POD" -n default --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1
step 1 "디버그 파드 기동 후 IAM 인증 토큰으로 RDS 접속"
progress "디버그 파드 기동 (postgres 클라이언트 이미지)"
K run "$POD" -n default --image=postgres:15-alpine --restart=Never --command -- sleep 300 >/dev/null
K wait --for=condition=Ready "pod/$POD" -n default --timeout=90s >/dev/null 2>&1 || { fail "디버그 파드가 Ready 상태가 안 됨"; result_box FAILED "디버그 파드 기동 실패"; scene_report 5 "RDS PII 이중 마스킹 + IAM DB Auth" FAILED "kubectl exec ... psql"; exit 1; }

# 토큰은 이 스크립트를 실행하는 쪽(여기)에서 생성해서 파드에 넘긴다 -
# postgres:15-alpine 이미지엔 aws-cli가 없고, IAM Auth 토큰은 서명한 주체의
# 네트워크 위치와 무관하게(제어 평면 API 호출일 뿐) 어디서 만들든 유효하므로
# 파드 안에 aws-cli를 따로 설치할 필요가 없다.
psql_as() {
  local dbuser="$1" sql="$2" token
  token=$(aws rds generate-db-auth-token --hostname "$RDS_HOST" --port 5432 --username "$dbuser" --region "$AWS_REGION")
  K exec "$POD" -n default -- env PGPASSWORD="$token" PGSSLMODE=require \
    psql "host=$RDS_HOST port=5432 dbname=demodb user=$dbuser" -t -c "$sql" 2>&1
}

step 2 "마스킹 뷰 조회 - salary 컬럼 NULL 마스킹 확인"
progress "general_user_readonly로 IAM 인증 접속 후 마스킹 뷰 조회 (salary는 NULL로 가려져야 함 - masked.employees_general 정의상)"
OUT1=$(psql_as general_user_readonly "SELECT email, salary FROM masked.employees_general LIMIT 3;")
echo "$OUT1"
# 각 행의 두 번째 컬럼(salary, '|' 뒤)이 비어있으면(NULL) 마스킹된 것.
SALARY_VALUES=$(echo "$OUT1" | awk -F'|' '{gsub(/ /,"",$2); print $2}')
if [ -z "$OUT1" ] || echo "$OUT1" | grep -qi "error\|denied\|timeout"; then
  fail "접속 또는 조회 실패"
  PASS=0
elif echo "$SALARY_VALUES" | grep -qE '[0-9]'; then
  threat "salary가 마스킹되지 않은 원본 숫자로 보임: $OUT1"
  PASS=0
else
  ok "salary가 NULL로 마스킹됨"
fi

step 3 "security_auditor_readonly 접속 및 IAM DB Auth 활성화 최종 확인"
progress "security_auditor_readonly로 감사용 뷰 조회 (접속 자체가 되는지만 확인)"
OUT2=$(psql_as security_auditor_readonly "SELECT count(*) FROM masked.employees_audit;")
echo "$OUT2"
if echo "$OUT2" | grep -qi "error\|denied\|timeout" || [ -z "$OUT2" ]; then
  fail "security_auditor_readonly 접속 실패"
  PASS=0
else
  ok "security_auditor_readonly IAM 인증 접속 성공"
fi

progress "IAM DB 인증 활성화 여부 (iam_database_authentication_enabled)"
IAM_AUTH=$(aws rds describe-db-instances --db-instance-identifier demo-project-dev-postgres-db --query 'DBInstances[0].IAMDatabaseAuthenticationEnabled' --output text)
if [ "$IAM_AUTH" = "True" ]; then
  ok "IAMDatabaseAuthenticationEnabled=True"
else
  fail "IAMDatabaseAuthenticationEnabled=$IAM_AUTH"
  PASS=0
fi

if [ "$PASS" = "1" ]; then
  result_box PASSED "PII 마스킹 정상 동작 + IAM DB Auth 활성화 확인"
  scene_report 5 "RDS PII 이중 마스킹 + IAM DB Auth" PASSED "kubectl exec <pod> -- psql (IAM 토큰)"
else
  result_box FAILED "마스킹 또는 IAM DB Auth 이상 발견"
  scene_report 5 "RDS PII 이중 마스킹 + IAM DB Auth" FAILED "kubectl exec <pod> -- psql (IAM 토큰)"
  exit 1
fi
