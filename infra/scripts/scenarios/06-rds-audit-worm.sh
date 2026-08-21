#!/usr/bin/env bash
# =============================================================================
# Scene 6: Kinesis Firehose → S3 Object Lock Compliance WORM & 삭제 방어 검증
# =============================================================================
# 두 가지를 확인한다: (1) RDS 로그 → Firehose → WORM 버킷 파이프라인이
# 설정대로 존재하는지, (2) Object Lock(Compliance 모드)이 실제로 삭제를
# 막는지 - 버킷에 테스트 객체를 하나 올리고 그 특정 버전을 지워보는 것으로
# 직접 증명한다(계정 소유자도 못 지운다는 게 이 씬의 핵심 주장이므로,
# 설정값만 읽는 것보다 실제로 시도해보는 게 훨씬 설득력 있음).
# 멱등: 같은 키로 매번 새 버전만 추가되고(락 걸린 버전은 지울 수 없어 원래
# 지우지도 않음), 실행마다 상태가 깨지지 않는다.
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 06 "Kinesis Firehose → S3 Object Lock Compliance WORM 삭제 방어 검증" \
  "RDS 감사로그 → Firehose 파이프라인 및 구독 필터 상태 확인" \
  "Object Lock Compliance 모드 설정 확인" \
  "테스트 객체 업로드 후 실제 삭제 시도 → AccessDenied로 거부되는지 실증"

BUCKET=$(tf_output rds_audit_worm_bucket)
PASS=1
KEY="verification-test/deletion-protection-check.txt"

step 1 "파이프라인 리소스 존재 확인 (Firehose, 구독 필터)"
STREAM=$(aws firehose describe-delivery-stream --delivery-stream-name demo-project-dev-rds-audit-worm-stream --query 'DeliveryStreamDescription.DeliveryStreamStatus' --output text 2>&1)
if [ "$STREAM" = "ACTIVE" ]; then
  ok "Firehose 스트림 ACTIVE"
else
  fail "Firehose 스트림 상태: $STREAM"
  PASS=0
fi

FILTER_PATTERN=$(aws logs describe-subscription-filters --log-group-name /aws/rds/instance/demo-project-dev-postgres-db/postgresql --query 'subscriptionFilters[0].filterPattern' --output text 2>&1)
if [ "$FILTER_PATTERN" = "AUDIT" ]; then
  ok "구독 필터 패턴이 'AUDIT'로 좁혀져 있음(전체 로그가 아니라 pgAudit 감사 로그만 통과)"
else
  fail "구독 필터 패턴: $FILTER_PATTERN (기대: AUDIT)"
  PASS=0
fi

step 2 "Object Lock 설정 확인 (Compliance 모드)"
LOCK_MODE=$(aws s3api get-object-lock-configuration --bucket "$BUCKET" --query 'ObjectLockConfiguration.Rule.DefaultRetention.Mode' --output text 2>&1)
if [ "$LOCK_MODE" = "COMPLIANCE" ]; then
  ok "기본 보존 모드 COMPLIANCE (계정 소유자 포함 누구도 기간 내 삭제 불가)"
else
  fail "Object Lock 모드: $LOCK_MODE (기대: COMPLIANCE)"
  PASS=0
fi

step 3 "실제 삭제 시도로 방어 증명"
echo "테스트 $(date -u +%FT%TZ)" > /tmp/worm-test.txt
aws s3 cp /tmp/worm-test.txt "s3://$BUCKET/$KEY" >/dev/null
VERSION_ID=$(aws s3api list-object-versions --bucket "$BUCKET" --prefix "$KEY" --query 'Versions[0].VersionId' --output text)
progress "올린 객체 버전: $VERSION_ID"

threat "잠긴 버전에 대해 강제 삭제 시도 중..."
DELETE_ERR=$(aws s3api delete-object --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION_ID" 2>&1 || true)
if echo "$DELETE_ERR" | grep -qi "AccessDenied\|not authorized\|Object is Governed"; then
  ok "특정 버전 삭제 시도가 AccessDenied로 거부됨(Object Lock이 실제로 동작 중)"
else
  fail "삭제가 거부되지 않음 - Object Lock이 실제로 걸려있지 않을 수 있음: $DELETE_ERR"
  PASS=0
fi

rm -f /tmp/worm-test.txt

if [ "$PASS" = "1" ]; then
  result_box PASSED "WORM 삭제 방어 정상 동작 확인"
  scene_report 6 "Firehose→S3 Object Lock WORM 삭제 방어" PASSED "aws s3api delete-object --version-id <locked>"
else
  result_box FAILED "WORM 파이프라인 또는 삭제 방어 이상 발견"
  scene_report 6 "Firehose→S3 Object Lock WORM 삭제 방어" FAILED "aws s3api delete-object --version-id <locked>"
  exit 1
fi
