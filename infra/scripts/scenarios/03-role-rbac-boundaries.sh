#!/usr/bin/env bash
# =============================================================================
# Scene 3: 세분화된 8개 IAM Role & K8s 네임스페이스/RBAC 접근 통제 검증
# =============================================================================
# ADR-019(8-Role) + 34-k8s-namespaces-rbac.tf의 경계가 실제로 지켜지는지
# kubectl auth can-i --as-group 임퍼스네이션으로 검증한다(실제 SAML 로그인
#없이도 RBAC 판정 자체를 확인 가능 - RoleBinding 판정은 그룹명에만 의존).
# 멱등: 상태를 바꾸지 않는 읽기 전용 점검이라 몇 번을 돌려도 결과가 같다.
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 03 "8개 IAM Role + K8s 네임스페이스 RBAC 경계 검증" \
  "dev-general/dev-lead/dev-hr-backend/security-auditor 그룹별 kubectl 권한 임퍼스네이션 조회" \
  "네임스페이스 간(frontend/employee-backend/hr-backend) 접근 경계 위반 여부 확인" \
  "8개 IAM Role의 Permission Boundary 부착 여부까지 최종 확인"

CLUSTER=$(tf_output eks_cluster_name)
KUBECONFIG_FILE=$(mktemp)
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" --kubeconfig "$KUBECONFIG_FILE" >/dev/null

K() { kubectl --kubeconfig "$KUBECONFIG_FILE" "$@"; }

PASS=1

check() {
  local desc="$1" expect="$2"; shift 2
  local got
  got=$(K auth can-i "$@" 2>/dev/null)
  if [ "$got" = "$expect" ]; then
    ok "$desc (기대=$expect, 실제=$got)"
  else
    fail "$desc (기대=$expect, 실제=$got) -- kubectl auth can-i $*"
    PASS=0
  fi
}

step 1 "네임스페이스별 RBAC 권한 임퍼스네이션 조회"
progress "dev-general: frontend/employee-backend 조회만 가능, 수정 불가, hr-backend 접근 불가"
check "frontend get pods"          yes get pods -n frontend --as=x --as-group=dev-general
check "frontend create pods"       no  create pods -n frontend --as=x --as-group=dev-general
check "employee-backend get pods"  yes get pods -n employee-backend --as=x --as-group=dev-general
check "hr-backend get pods"        no  get pods -n hr-backend --as=x --as-group=dev-general

progress "dev-lead: frontend/employee-backend 조회+수정 가능, hr-backend 접근 불가"
check "frontend create pods"       yes create pods -n frontend --as=x --as-group=dev-lead
check "employee-backend delete pods" yes delete pods -n employee-backend --as=x --as-group=dev-lead
check "hr-backend get pods"        no  get pods -n hr-backend --as=x --as-group=dev-lead

step 2 "네임스페이스 간 접근 경계 위반 여부 확인"
progress "dev-hr-backend: hr-backend만 수정 가능, frontend/employee-backend 접근 불가"
check "hr-backend create pods"     yes create pods -n hr-backend --as=x --as-group=dev-hr-backend
check "frontend get pods"          no  get pods -n frontend --as=x --as-group=dev-hr-backend

progress "security-auditor: 전 네임스페이스 조회만 가능, 수정 불가"
check "hr-backend get pods"        yes get pods -n hr-backend --as=x --as-group=security-auditor
check "frontend get pods"          yes get pods -n frontend --as=x --as-group=security-auditor
check "hr-backend create pods"     no  create pods -n hr-backend --as=x --as-group=security-auditor

step 3 "8개 IAM Role의 Permission Boundary 부착 여부 확인"
for role in dev-general dev-lead dev-hr-backend db-general db-lead ops-general ops-lead security-auditor; do
  ROLE_NAME="demo-project-dev-${role}"
  BOUNDARY=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text 2>/dev/null)
  if [ "$BOUNDARY" != "None" ] && [ -n "$BOUNDARY" ]; then
    ok "$ROLE_NAME - Permission Boundary 부착됨"
  else
    fail "$ROLE_NAME - Permission Boundary 없음"
    PASS=0
  fi
done

rm -f "$KUBECONFIG_FILE"

if [ "$PASS" = "1" ]; then
  result_box PASSED "8개 Role/RBAC 경계 위반 없음"
  scene_report 3 "IAM Role 8종 + K8s RBAC 경계" PASSED "kubectl auth can-i --as-group=<role>"
else
  result_box FAILED "RBAC 경계 또는 Permission Boundary 이상 발견"
  scene_report 3 "IAM Role 8종 + K8s RBAC 경계" FAILED "kubectl auth can-i --as-group=<role>"
  exit 1
fi
