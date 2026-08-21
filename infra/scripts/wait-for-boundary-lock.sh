#!/usr/bin/env bash
# =============================================================================
# Slack "Lock & Revoke" 클릭 직후 실제로 AWS 쪽 Deny 정책이 반영되는 순간을
# 폴링해서 알려주는 스크립트 (촬영용 타이밍 파악)
# =============================================================================
# IAM 정책 변경(특히 이미 발급된 세션에 대한 Deny)은 AWS 인프라 전체에 퍼지는 데
# "최대 몇 분" 걸릴 수 있다고 AWS가 공식 문서에 명시하고 있고, 정확한 시간은
# AWS도 보장하지 않는다(session-revoke.py 주석 참고). 라이브로 "Lock 누르고
# 바로 막히는지" 한 테이크에 담으려 하면 타이밍이 안 맞아 NG날 수 있어서,
# 이 스크립트를 별도 터미널(화면 밖)에서 돌려두고 실제로 막히는 순간을 먼저
# 확인한 뒤, 메인 촬영 터미널로 돌아가 그 명령을 라이브로 다시 입력해서
# AccessDenied 뜨는 장면만 촬영하는 방식을 권장한다.
#
# ⚠️ IAM은 여러 리전/가용영역에 분산된 인증 평가 노드(엣지)를 쓰기 때문에,
# Deny 정책이 "전파되는 도중"에는 어느 노드가 요청을 받느냐에 따라 같은
# 명령이 막혔다 안 막혔다를 반복할 수 있다(실측으로 확인 - 첫 AccessDenied가
# 뜬 직후 바로 재실행했더니 다시 성공하는 현상). 그래서 이 스크립트는 이제
# "AccessDenied를 한 번 봤다"가 아니라 "연속으로 CONSECUTIVE_NEEDED번 계속
# AccessDenied가 나온다"를 확인해야 완전히 안정된 것으로 판단한다.
#
# 사용법: bash wait-for-boundary-lock.sh [프로필명] [폴링 간격(초)] [연속 필요 횟수]
#   기본값: 프로필 dev-general-demo, 10초 간격, 연속 3회
set -uo pipefail

PROFILE="${1:-dev-general-demo}"
INTERVAL="${2:-10}"
CONSECUTIVE_NEEDED="${3:-3}"

echo "▶ ${PROFILE} 프로필로 eks:ListClusters가 '안정적으로' 막히는 순간을 폴링합니다"
echo "  (${INTERVAL}초 간격, AccessDenied가 연속 ${CONSECUTIVE_NEEDED}번 나와야 완료로 판단 - 전파 중 오락가락 방지)"
START=$(date +%s)
STREAK=0
FIRST_DENY_ELAPSED=""
while true; do
  RESULT=$(aws eks list-clusters --profile "$PROFILE" 2>&1)
  NOW=$(date -u +%T)
  if echo "$RESULT" | grep -q "AccessDenied"; then
    STREAK=$(( STREAK + 1 ))
    if [ -z "$FIRST_DENY_ELAPSED" ]; then
      FIRST_DENY_ELAPSED=$(( $(date +%s) - START ))
    fi
    echo "  막힘 (${STREAK}/${CONSECUTIVE_NEEDED} 연속) ($NOW)"
    if [ "$STREAK" -ge "$CONSECUTIVE_NEEDED" ]; then
      ELAPSED=$(( $(date +%s) - START ))
      echo "✅ 안정적으로 막힘 확인! 총 경과: ${ELAPSED}초 ($(( ELAPSED / 60 ))분 $(( ELAPSED % 60 ))초)"
      echo "   (참고: 첫 AccessDenied는 ${FIRST_DENY_ELAPSED}초에 떴지만, 그 뒤로도 전파가 덜 끝나 잠깐 다시 성공했을 수 있음)"
      break
    fi
  else
    if [ "$STREAK" -gt 0 ]; then
      echo "  ⚠️  다시 성공함 - 아직 전파 중(연속 스트릭 초기화) ($NOW)"
    else
      echo "  아직 안 막힘... ($NOW)"
    fi
    STREAK=0
    FIRST_DENY_ELAPSED=""
  fi
  sleep "$INTERVAL"
done
