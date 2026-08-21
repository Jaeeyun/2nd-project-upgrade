#!/usr/bin/env bash
# =============================================================================
# Scene 8: AWS ASR — 보안 오설정(SSH 0.0.0.0/0) 감지 → 자동조치 원복 검증
# =============================================================================
# 43-demo-scenario-resources.tf의 전용 더미 보안그룹에만 오설정을 낸다(실제
# 서비스 SG는 절대 건드리지 않음). Security Hub가 실제로 이 SG의 finding을
# 만드는 데는 Config 재평가 주기상 몇 분~몇 시간이 걸릴 수 있어(촬영 중
# 반복 재현에 부적합), 검증 스크립트는 ASR 런북(ASR-SC_2.0.0_EC2.13)이
# 내부적으로 호출하는 것과 동일한 AWS 네이티브 런북
# (AWS-DisablePublicAccessForSecurityGroup)을 ASR이 만든 전용 Role로 직접
# 실행해서 "탐지되면 실제로 고쳐지는 능력" 자체를 검증한다. 실제 Security
# Hub Custom Action 클릭 → 전체 체인은 촬영 시점에 실제 finding이 잡힌
# 뒤 사람이 직접 눌러서 보여준다.
# 멱등: 실행할 때마다 먼저 오설정을 만들고 나서 고치므로, 끝나면 항상
# SSH 룰이 없는 정상 상태로 돌아온다.
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 08 "ASR 보안 오설정(SSH 0.0.0.0/0) 탐지 → 자동조치 원복 검증" \
  "더미 보안그룹에 SSH(22) 0.0.0.0/0 인바운드 오설정 고의 생성" \
  "ASR 런북(AWS-DisablePublicAccessForSecurityGroup) 자동 실행" \
  "SSH 룰 자동 제거 및 정상 상태 원복 확인"

SG_ID=$(tf_output asr_demo_target_sg_id)
ROLE_ARN=$(aws iam get-role --role-name "SO0111-DisablePublicAccessForSecurityGroup-asrdemo" --query 'Role.Arn' --output text)
PASS=1

has_ssh_open() {
  aws ec2 describe-security-groups --group-ids "$SG_ID" \
    --query "SecurityGroups[0].IpPermissions[?ToPort==\`22\` && contains(IpRanges[].CidrIp, '0.0.0.0/0')]" \
    --output text
}

step 1 "보안 오설정 고의 생성"
threat "오설정 생성: $SG_ID 에 SSH(22) 0.0.0.0/0 인바운드 추가"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
if [ -n "$(has_ssh_open)" ]; then
  ok "오설정 생성 확인됨"
else
  fail "오설정을 만들지 못함"
  PASS=0
fi

step 2 "ASR 런북 자동 실행"
progress "ASR 런북(AWS-DisablePublicAccessForSecurityGroup)을 ASR 전용 Role로 실행"
EXEC_ID=$(aws ssm start-automation-execution \
  --document-name "AWS-DisablePublicAccessForSecurityGroup" \
  --parameters "GroupId=$SG_ID,AutomationAssumeRole=$ROLE_ARN" \
  --query 'AutomationExecutionId' --output text)
progress "실행 ID: $EXEC_ID"

for _ in $(seq 1 24); do
  sleep 5
  STATUS=$(aws ssm get-automation-execution --automation-execution-id "$EXEC_ID" --query 'AutomationExecution.AutomationExecutionStatus' --output text)
  [ "$STATUS" != "InProgress" ] && [ "$STATUS" != "Pending" ] && break
done
progress "최종 상태: $STATUS"

step 3 "SSH 룰 자동 제거 및 정상 상태 원복 확인"
if [ "$STATUS" = "Success" ] && [ -z "$(has_ssh_open)" ]; then
  ok "자동조치로 SSH 룰이 제거됨"
else
  fail "자동조치 실패 또는 SSH 룰이 남아있음"
  PASS=0
  # 안전장치: 자동조치가 실패했어도 검증 스크립트가 오설정을 남겨두면 안 되므로 직접 정리
  aws ec2 revoke-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null 2>&1 || true
fi

if [ "$PASS" = "1" ]; then
  result_box PASSED "SSH 오설정 자동 탐지 및 원복 완료"
  scene_report 8 "ASR 오설정(SSH 0.0.0.0/0) 탐지→자동 원복" PASSED "aws ssm start-automation-execution AWS-DisablePublicAccessForSecurityGroup"
else
  result_box FAILED "자동조치 실패 또는 SSH 룰 잔존"
  scene_report 8 "ASR 오설정(SSH 0.0.0.0/0) 탐지→자동 원복" FAILED "aws ssm start-automation-execution AWS-DisablePublicAccessForSecurityGroup"
  exit 1
fi
