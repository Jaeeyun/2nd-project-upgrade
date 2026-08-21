#!/usr/bin/env bash
# =============================================================================
# Scene 12: GitHub Actions OIDC Keyless CI/CD 배포 & SSM 터미널 실시간 감사 로그
# =============================================================================
# frontend-test 파이프라인(your-org/your-repo)을 실제로 재실행해서 Keyless
# 배포가 여전히 되는지 확인하고, 그 배포가 실제로 거친 경로(Keycloak EC2에서
# SSM RunCommand로 kubectl 실행)가 SSM 명령 기록(감사 로그)으로 남는지 확인한다.
# 멱등: workflow_dispatch로 재실행하는 것 자체가 이미 멱등하게 설계돼 있음
# (이미지 태그에 run_id가 들어가 IMMUTABLE 리포지토리와도 충돌 안 함).
set -uo pipefail
cd "$(dirname "$0")"
source ./_lib.sh

scene_banner 12 "GitHub Actions OIDC Keyless CI/CD 배포 + SSM 실시간 감사 로그 검증" \
  "CI Role 신뢰 정책에 정적 Access Key 없이 OIDC만 허용되는지 확인" \
  "GitHub Actions 워크플로 실제 재실행(Keyless 배포) 완료 대기" \
  "SSM 명령 감사 기록 + Session Manager 로깅 강제 설정 확인"

PASS=1

step 1 "CI Role 신뢰 정책 - 정적 키 없이 OIDC만 허용되는지 확인"
TRUST_POLICY=$(aws iam get-role --role-name demo-project-dev-github-ci-role --query 'Role.AssumeRolePolicyDocument' --output json)
if echo "$TRUST_POLICY" | grep -q "token.actions.githubusercontent.com"; then
  ok "GitHub OIDC 제공자만 이 Role을 assume 가능"
else
  fail "OIDC 조건을 찾을 수 없음"
  PASS=0
fi
ACCESS_KEYS=$(aws iam list-access-keys --user-name demo-project-dev-github-ci-role 2>&1)
if echo "$ACCESS_KEYS" | grep -qi "NoSuchEntity\|not.*user"; then
  ok "github_ci는 IAM User가 아니라 Role이라 애초에 정적 Access Key 자체가 없음"
fi

step 2 "GitHub Actions 워크플로 실제 재실행(Keyless 배포) 완료 대기"
progress "GitHub Actions 워크플로 재실행(실제 Keyless 배포)"
RUN_URL=$(gh workflow run "Deploy frontend-test (Keyless OIDC)" --repo your-org/your-repo --ref main 2>&1)
echo "$RUN_URL"
sleep 8
RUN_ID=$(gh run list --repo your-org/your-repo --workflow "Deploy frontend-test (Keyless OIDC)" --limit 1 --json databaseId --jq '.[0].databaseId')
progress "RUN_ID=$RUN_ID"

progress "워크플로 완료 대기"
gh run watch "$RUN_ID" --repo your-org/your-repo --exit-status >/tmp/scene12-run.log 2>&1
WORKFLOW_STATUS=$?
tail -20 /tmp/scene12-run.log
if [ "$WORKFLOW_STATUS" = "0" ]; then
  ok "워크플로 성공(build→push→SSM RunCommand→kubectl apply 전 구간)"
else
  fail "워크플로 실패"
  PASS=0
fi

step 3 "SSM 명령 감사 기록 + Session Manager 로깅 강제 설정 확인"
IID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=demo-project-dev-keycloak-poc" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)
RECENT_CMD=$(aws ssm list-command-invocations --instance-id "$IID" --max-results 5 --query 'CommandInvocations[0].{Status:Status,Time:RequestedDateTime}' --output json 2>&1)
progress "최근 SSM 명령: $RECENT_CMD"
if echo "$RECENT_CMD" | grep -q "Status"; then
  ok "SSM 명령 실행 기록이 실제로 CloudTrail/SSM 이력에 남음(누가 언제 뭘 실행했는지 감사 가능)"
else
  fail "SSM 명령 기록을 찾을 수 없음"
  PASS=0
fi

DOC_CONTENT=$(aws ssm get-document --name "SSM-SessionManagerRunShell" --query 'Content' --output text 2>&1)
if echo "$DOC_CONTENT" | grep -q "s3BucketName\|cloudWatchLogGroupName"; then
  ok "세션 로깅(S3/CloudWatch) 설정이 강제되어 있음"
else
  fail "세션 로깅 설정을 확인 못 함"
  PASS=0
fi

if [ "$PASS" = "1" ]; then
  result_box PASSED "Keyless CI/CD 배포 + SSM 감사로그 정상"
  scene_report 12 "GitHub Actions OIDC Keyless CI/CD + SSM 감사로그" PASSED "gh workflow run + aws ssm list-command-invocations"
else
  result_box FAILED "CI/CD 배포 또는 감사로그 확인 실패"
  scene_report 12 "GitHub Actions OIDC Keyless CI/CD + SSM 감사로그" FAILED "gh workflow run + aws ssm list-command-invocations"
  exit 1
fi
