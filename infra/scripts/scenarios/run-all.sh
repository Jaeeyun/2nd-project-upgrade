#!/usr/bin/env bash
# =============================================================================
# 10개 시나리오(Scene 3,5,6,7,8,9,10,11,12,13) 전체 실행 + 종합 리포트
# =============================================================================
# 각 씬 스크립트는 전부 독립적으로 멱등하게 동작하도록 만들어졌다(먼저
# 정리→재현→검증→정리 순서). 이 스크립트는 그것들을 순서대로 실행하고
# [Scene | 목적 | 실행 명령어 | PASSED/FAILED] 표를 마지막에 모아서 보여준다.
#
# Scene 8, 9, 11은 실제 AWS 서비스(ASR SSM Automation, RDS 실접속, IAM
# Access Analyzer Policy Generation)를 기다리는 구간이 있어 전체 실행에
# 5~8분 정도 걸릴 수 있다.
#
# 사용법: ./run-all.sh
set -uo pipefail
cd "$(dirname "$0")"

SCRIPTS=(
  "03-role-rbac-boundaries.sh"
  "05-rds-pii-masking.sh"
  "06-rds-audit-worm.sh"
  "07-eks-pod-isolation.sh"
  "08-asr-remediation.sh"
  "09-permission-drift.sh"
  "10-session-revocation.sh"
  "11-boundary-drift.sh"
  "12-cicd-oidc-audit.sh"
  "13-grafana-soc-dashboard.sh"
)

REPORT_LINES=()
OVERALL_PASS=1
START_TS=$(date +%s)

echo "════════════════════════════════════════════════════════════════"
echo " 10개 시나리오 전체 실행 시작 - $(date -u +%FT%TZ)"
echo "════════════════════════════════════════════════════════════════"

for script in "${SCRIPTS[@]}"; do
  echo
  echo "──────────────────────────────────────────────────────────────"
  echo " ▶▶▶ 실행: $script"
  echo "──────────────────────────────────────────────────────────────"
  OUT=$(./"$script" 2>&1)
  echo "$OUT"
  LINE=$(echo "$OUT" | grep -E "^\| Scene" | tail -1)
  if [ -n "$LINE" ]; then
    REPORT_LINES+=("$LINE")
  else
    REPORT_LINES+=("| Scene ?  | $script (리포트 라인 파싱 실패)                     | FAILED  | -")
  fi
  echo "$LINE" | grep -q "FAILED" && OVERALL_PASS=0
done

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))

echo
echo "════════════════════════════════════════════════════════════════"
echo " 종합 결과 (총 소요: ${ELAPSED}초)"
echo "════════════════════════════════════════════════════════════════"
printf '| %-8s | %-53s | %-7s | %s\n' "Scene" "목적" "결과" "핵심 명령어"
printf '|%s|%s|%s|%s\n' "----------" "-------------------------------------------------------" "---------" "----------------------------------------"
for line in "${REPORT_LINES[@]}"; do
  echo "$line"
done

echo
if [ "$OVERALL_PASS" = "1" ]; then
  echo "✅ 전체 10개 시나리오 PASSED - 촬영 대기 상태로 세팅 완료"
else
  echo "❌ 일부 시나리오 FAILED - 위 표에서 FAILED 항목 확인 필요"
  exit 1
fi
