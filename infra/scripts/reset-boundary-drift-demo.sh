#!/usr/bin/env bash
# =============================================================================
# 권한 드리프트 축소 데모(36-ciem-boundary-drift-check.tf) 리셋
# =============================================================================
# Slack "✅ 이 권한들 제거" 버튼을 누르면 ciem-key-exception-callback.py의
# _handle_apply_reduced_policy가 aws_iam_role_policy.standard[role_suffix]를
# Console/CLI 경로(iam:PutRolePolicy)로 직접 덮어써서, Terraform 상태
# (policies/*.json.tpl 원본)와 실제 AWS 상태가 어긋난다. 다음 테이크를
# "Clean Ready State"로 되돌리려면 그 Role 하나만 -target으로 다시 apply해서
# 원래 전체 정책(축소 전)으로 복원한다.
#
# 사용법: bash reset-boundary-drift-demo.sh <role-suffix>
# 예시:   bash reset-boundary-drift-demo.sh dev-general
set -euo pipefail

ROLE_SUFFIX="${1:?사용법: $0 <role-suffix>}"

# terraform apply/output은 project-c 디렉터리에서 실행해야 한다 - 다른 경로에서
# 부르면 에러 없이 빈 문자열/엉뚱한 상태로 진행될 수 있어서(trigger-boundary-
# drift-check.sh에서 실측 확인된 문제와 동일) 스크립트 위치 기준으로 강제 이동.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

TARGET="aws_iam_role_policy.standard[\"${ROLE_SUFFIX}\"]"

echo "▶ ${TARGET} 를 policies/*.json.tpl 원본 정책으로 되돌립니다"
terraform apply -target="$TARGET" -auto-approve

echo ""
echo "▶ 최종 확인 (복원된 정책의 Action 목록)"
NAME_PREFIX=$(terraform output -raw name_prefix)
ROLE_NAME="${NAME_PREFIX}-${ROLE_SUFFIX}"
POLICY_NAME=$(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[0]' --output text)
aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$POLICY_NAME" \
  --query 'PolicyDocument.Statement[*].Action'

echo ""
echo "Clean Ready State 완료 (${ROLE_SUFFIX})."
echo "⚠️ 방금 복원된 넓은 정책도 IAM 전파 지연(최대 몇 분) 대상입니다 - 바로 다음 테이크를"
echo "  찍기 전에 wait-for-command-denied.sh 등으로 실제로 다시 풀렸는지 확인하는 걸 권장합니다."
