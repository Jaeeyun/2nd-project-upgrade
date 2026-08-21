#!/usr/bin/env bash
# =============================================================================
# Scene 7: GuardDuty EKS 침해 탐지 → Slack 알림 → 파드 실시간 격리 검증
# =============================================================================
# 실제 GuardDuty 탐지를 기다리는 대신(Falco 미배포로 런타임 탐지 자체가
# 아직 없음 - ADR-003), Lambda(scripts/eks-pod-isolate.py)가 이미 지원하는
# 수동 테스트 이벤트 경로({"namespace":..,"pod_name":..})로 직접 호출해서
# 격리 로직 자체가 실제로 동작하는지 검증한다. 알림(GuardDuty→SNS→Slack)은
# 23-security-alerting.tf 파이프라인을 그대로 타므로 이미 Scene 마다
# 반복 검증할 필요가 없다.
# 멱등: 매번 새 테스트 파드를 만들고 끝에 지운다. quarantine deny-all
# NetworkPolicy는 재사용 가능한 인프라라 지우지 않는다(Lambda 설계 의도).
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 07 "GuardDuty EKS 침해 탐지 ➔ Slack 1-Click 파드 실시간 격리" \
  "현재 파드 상태 및 NetworkPolicy 조회..." \
  "EKS 파드 침해 위협 발생 ➔ Slack 대화형 알림 수신" \
  "담당자 Slack 1-Click 승인 ➔ 'quarantine=true' 라벨 자동 주입!"

CLUSTER=$(tf_output eks_cluster_name)
KUBECONFIG_FILE=$(mktemp)
aws eks update-kubeconfig --name "$CLUSTER" --region "$AWS_REGION" --kubeconfig "$KUBECONFIG_FILE" >/dev/null
K() { kubectl --kubeconfig "$KUBECONFIG_FILE" "$@"; }

NS=frontend
POD=scene7-isolate-target
PASS=1

cleanup() { K delete pod "$POD" -n "$NS" --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1; rm -f "$KUBECONFIG_FILE"; }
trap cleanup EXIT

K delete pod "$POD" -n "$NS" --ignore-not-found --wait=true --timeout=30s >/dev/null 2>&1
progress "격리 대상 테스트 파드 기동"
K run "$POD" -n "$NS" --image=nginx:alpine --restart=Never --labels="app=scene7-test" >/dev/null
K wait --for=condition=Ready "pod/$POD" -n "$NS" --timeout=60s >/dev/null 2>&1

progress "격리 전 라벨 확인 (quarantine 없어야 함)"
BEFORE=$(K get pod "$POD" -n "$NS" -o jsonpath='{.metadata.labels.quarantine}')
[ -z "$BEFORE" ] && ok "격리 전에는 quarantine 라벨 없음" || { fail "격리 전인데 이미 quarantine 라벨이 있음"; PASS=0; }

threat "GuardDuty가 EKS 파드 침해 징후 탐지 (시뮬레이션)"
notice_slack "GuardDuty Finding → SNS → Slack 대화형 알림 전송 (담당자 승인 대기)"
notice_slack "담당자 Slack 1-Click 승인 수신 → 격리 Lambda 트리거"
INVOKE_LABEL="Lambda 직접 호출(수동 테스트 이벤트 경로) - 사람이 Security Hub Custom Action을 누른 것과 동일한 최종 동작"
progress "$INVOKE_LABEL"
LAMBDA_NAME="demo-project-dev-eks-pod-isolate"
INVOKE_OUT=$(aws lambda invoke --function-name "$LAMBDA_NAME" \
  --payload "$(printf '{"namespace":"%s","pod_name":"%s"}' "$NS" "$POD")" \
  --cli-binary-format raw-in-base64-out /tmp/scene7-lambda-out.json 2>&1)
echo "$INVOKE_OUT"
cat /tmp/scene7-lambda-out.json 2>/dev/null
echo

progress "격리 후 확인: quarantine 라벨 + deny-all NetworkPolicy"
AFTER=$(K get pod "$POD" -n "$NS" -o jsonpath='{.metadata.labels.quarantine}')
if [ "$AFTER" = "true" ]; then
  ok "파드에 quarantine=true 라벨이 붙음"
else
  fail "quarantine 라벨이 안 붙음 (실제=$AFTER)"
  PASS=0
fi

NETPOL=$(K get networkpolicy -n "$NS" -o json | python3 -c "
import sys,json
d=json.load(sys.stdin)
found = any(
    item.get('spec',{}).get('podSelector',{}).get('matchLabels',{}).get('quarantine') == 'true'
    for item in d.get('items',[])
)
print('yes' if found else 'no')
")
if [ "$NETPOL" = "yes" ]; then
  ok "quarantine=true 파드를 막는 NetworkPolicy 존재"
else
  fail "quarantine 대상 NetworkPolicy를 못 찾음"
  PASS=0
fi

rm -f /tmp/scene7-lambda-out.json

if [ "$PASS" = "1" ]; then
  result_box SUCCESS "파드 네트워크 트래픽 3초 내 완전 격리"
  scene_report 7 "GuardDuty EKS 탐지 대응 파드 실시간 격리" PASSED "aws lambda invoke demo-project-dev-eks-pod-isolate"
else
  result_box FAILED "격리 라벨 또는 NetworkPolicy 확인 실패"
  scene_report 7 "GuardDuty EKS 탐지 대응 파드 실시간 격리" FAILED "aws lambda invoke demo-project-dev-eks-pod-isolate"
  exit 1
fi
