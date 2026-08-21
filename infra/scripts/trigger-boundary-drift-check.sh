#!/usr/bin/env bash
# =============================================================================
# 권한 드리프트 검사(36-ciem-boundary-drift-check.tf) 수동 즉시 실행
# =============================================================================
# ciem-boundary-drift-notify.py는 원래 EventBridge Scheduler가
# boundary_drift_lookback_hours(기본 3시간)마다 Role별로 자동 호출하지만,
# 촬영 중에 3시간을 실제로 기다릴 수 없으므로 이 스크립트로 즉시 같은
# payload({"role_suffix": "..."})로 수동 호출합니다 - 스케줄러가 부르는 것과
# 100% 동일한 Lambda/코드 경로입니다.
#
# ⚠️ 비동기(Event) 호출입니다. Access Analyzer Policy Generation 자체가
# 보통 1~3분, 길면 7분 가까이 걸려서(Lambda timeout 540초) 동기 호출로
# 기다리면 aws cli 쪽 read timeout(기본 60초)에 먼저 걸려 에러로 보일 수
# 있습니다 - 실제로는 Lambda가 그대로 계속 실행되니 걱정할 필요 없지만
# 혼란을 피하려 비동기로 던지고, 진행상황은 CloudWatch Logs나 Slack에서
# 직접 확인하는 방식을 씁니다.
#
# ⚠️ Access Analyzer는 CloudTrail의 "실시간 이벤트"가 아니라 S3에 저장된
# CloudTrail 로그 파일을 읽습니다. CloudTrail이 S3로 로그를 내보내는 데
# 보통 5분 정도 걸리므로, 방금 막 실행한 명령은 이 검사에 안 잡힐 수
# 있습니다 - 데모용 활동(eks:ListClusters 등)은 최소 10~15분 전에 미리
# 만들어두는 걸 권장합니다.
#
# 사용법: bash trigger-boundary-drift-check.sh <role-suffix>
# 예시:   bash trigger-boundary-drift-check.sh dev-general
set -euo pipefail

ROLE_SUFFIX="${1:?사용법: $0 <role-suffix> (dev-general/dev-lead/dev-hr-backend/db-general/db-lead/ops-general/ops-lead)}"

# terraform output은 project-c 디렉터리에서 실행해야 한다 - 다른 경로(예:
# 홈 디렉터리)에서 부르면 에러 없이 그냥 빈 문자열을 내놓고 넘어가버려서
# (실측 확인됨) FUNCTION_NAME이 "-ciem-boundary-drift-notify"처럼 깨진 채로
# 계속 진행되는 문제가 있었다. 스크립트 위치 기준으로 project-c로 강제 이동.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

NAME_PREFIX=$(terraform output -raw name_prefix)
FUNCTION_NAME="${NAME_PREFIX}-ciem-boundary-drift-notify"
OUT_FILE=$(mktemp)

echo "▶ ${FUNCTION_NAME} 비동기 호출 (role_suffix=${ROLE_SUFFIX})"
aws lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --invocation-type Event \
  --cli-binary-format raw-in-base64-out \
  --payload "{\"role_suffix\": \"${ROLE_SUFFIX}\"}" \
  "$OUT_FILE" >/dev/null

STATUS_CODE=$(python3 -c "import json;print(json.load(open('$OUT_FILE')).get('StatusCode','?'))" 2>/dev/null || echo "?")
echo "  접수됨 (StatusCode: ${STATUS_CODE}, 202면 정상 접수)"
rm -f "$OUT_FILE"

echo ""
echo "▶ Policy Generation 진행상황을 실시간으로 보려면 (보통 1~3분, 최대 7분 소요):"
echo "   aws logs tail /aws/lambda/${FUNCTION_NAME} --follow --since 5m"
echo ""
echo "▶ 결과가 result=flagged면 Slack #cspm-findings 채널에 '✅ 이 권한들 제거' 버튼과 함께 알림이 옵니다."
echo "  result=no_drift면 최근 활동이 정책 전체를 다 커버함(미사용 권한 없음) - 다른 Role로 시도하거나"
echo "  일부러 정책 안의 일부 액션만 써보고 재시도하세요."
