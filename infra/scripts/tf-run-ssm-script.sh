#!/usr/bin/env bash
# =============================================================================
# 로컬 쉘 스크립트 파일을 SSM RunCommand(AWS-RunShellScript)로 원격 EC2에서
# 실행하고 완료까지 기다리는 범용 헬퍼. terraform의 null_resource local-exec에서
# 호출한다(Grafana SAML 클라이언트 등록 등 - 25-grafana.tf 참고).
#
# 스크립트 파일 내용을 줄 단위로 그대로 SSM commands 배열에 담아 보내기 때문에
# (별도 이스케이프 없이) 원본 스크립트의 heredoc/멀티라인 구문이 그대로
# 보존된다 - Terraform HCL heredoc 안에 원격 스크립트 전체를 직접 박아넣으면
# bash의 ${VAR} 문법이 Terraform 보간 문법과 충돌하므로 이 방식을 쓴다.
#
# 사용법: tf-run-ssm-script.sh <instance-id> <region> <local-script-path> [ENV_KEY=VALUE ...]
set -euo pipefail

INSTANCE_ID="$1"
REGION="$2"
SCRIPT_PATH="$3"
shift 3

PARAMS_FILE=$(mktemp)
python3 -c "
import json, sys
env_kvs = sys.argv[1:]
env_lines = ['export ' + kv for kv in env_kvs]
script_lines = open('$SCRIPT_PATH').read().splitlines()
json.dump({'commands': env_lines + script_lines}, open('$PARAMS_FILE', 'w'))
" "$@"

CMD_ID=$(aws ssm send-command --document-name "AWS-RunShellScript" \
  --instance-ids "$INSTANCE_ID" --region "$REGION" \
  --parameters "file://$PARAMS_FILE" \
  --query 'Command.CommandId' --output text)
echo "SSM CommandId=$CMD_ID ($SCRIPT_PATH on $INSTANCE_ID)"
rm -f "$PARAMS_FILE"

STATUS="Pending"
for _ in $(seq 1 60); do
  STATUS=$(aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --region "$REGION" \
    --query 'Status' --output text 2>/dev/null || echo "Pending")
  [ "$STATUS" != "Pending" ] && [ "$STATUS" != "InProgress" ] && break
  sleep 5
done

echo "--- stdout ---"
aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --region "$REGION" \
  --query 'StandardOutputContent' --output text
echo "--- stderr ---"
aws ssm get-command-invocation --command-id "$CMD_ID" --instance-id "$INSTANCE_ID" --region "$REGION" \
  --query 'StandardErrorContent' --output text >&2

if [ "$STATUS" != "Success" ]; then
  echo "SSM 명령 실패 또는 타임아웃: status=$STATUS" >&2
  exit 1
fi
