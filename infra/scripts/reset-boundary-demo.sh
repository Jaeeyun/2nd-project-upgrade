#!/usr/bin/env bash
# =============================================================================
# Scene 3 보너스 컷(AdministratorAccess 부착 → Permission Boundary 시연) 리셋
# =============================================================================
# dev-general Role에 남아있는 관리형 정책을 전부 detach하고, 아직 미해결
# 상태로 남아있는 44-iam-boundary-violation-watch.tf 위반 이벤트를 전부
# RESOLVED로 정리해서 다음 테이크를 "Clean Ready State"로 만든다.
#
# CloudWatch Logs는 append-only라 기존 로그를 지울 수 없으므로, 같은
# event_id로 RESOLVED summary를 새로 남겨서 Grafana의 dedup 기반 LEFT
# 패널(🔴 Unresolved Drift Alerts)에서 자동으로 빠지게 한다
# (docs/grafana/grafana-soc-dashboard.json 패널 8 참고).
#
# "Lock & Revoke" 버튼을 실제로 눌렀다면 session-revoke.py가 8개 Role에
# revoke-session-<username> Deny 정책을 붙이고 Keycloak 계정을
# enabled=false로 비활성화까지 했을 수 있다 - 이것도 같이 원복한다
# (안 그러면 다음 테이크에서 saml2aws login 자체가 막힘).
set -uo pipefail

ROLE_NAME="demo-project-dev-dev-general"
DEMO_USERNAME="${1:-test-dev-general}"
LOG_GROUP="/demo-project/iam-boundary-violations"
REGION="ap-northeast-2"
ALL_ROLES=(
  demo-project-dev-db-general demo-project-dev-db-lead demo-project-dev-dev-general
  demo-project-dev-dev-hr-backend demo-project-dev-dev-lead demo-project-dev-ops-general
  demo-project-dev-ops-lead demo-project-dev-security-auditor
)

echo "▶ ${ROLE_NAME}에 붙은 관리형 정책 전부 detach"
ATTACHED=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" --region "$REGION" \
  --query 'AttachedPolicies[].PolicyArn' --output text)
if [ -z "$ATTACHED" ]; then
  echo "  (이미 없음)"
else
  for arn in $ATTACHED; do
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$arn" --region "$REGION"
    echo "  detached: $arn"
  done
fi

echo "▶ 미해결(UNRESOLVED) 이벤트 조회 및 RESOLVED 처리"
STREAM=$(date -u +%Y-%m-%d)
NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# 오늘 스트림의 모든 로그 라인을 훑어서, event_id별 "가장 최근 상태"가
# UNRESOLVED인 것만 골라 RESOLVED로 덮어쓴다(순수 셸+파이썬, dedup은
# Grafana 쪽에서 하는 방식을 여기서도 그대로 재현).
python3 -c "
import json, subprocess, time

REGION = '$REGION'
LOG_GROUP = '$LOG_GROUP'
STREAM = '$STREAM'

out = subprocess.run(
    ['aws', 'logs', 'get-log-events', '--log-group-name', LOG_GROUP,
     '--log-stream-name', STREAM, '--region', REGION, '--output', 'json'],
    capture_output=True, text=True,
)
if out.returncode != 0:
    print('  (오늘 로그 스트림 없음 - 정리할 게 없음)')
    raise SystemExit(0)

events = json.loads(out.stdout).get('events', [])
latest = {}
for e in events:
    try:
        msg = json.loads(e['message'])
    except (json.JSONDecodeError, KeyError):
        continue
    eid = msg.get('event_id')
    if not eid:
        continue
    latest[eid] = msg.get('summary', '')

unresolved = [eid for eid, s in latest.items() if s.startswith('UNRESOLVED')]
if not unresolved:
    print('  미해결 이벤트 없음 - 이미 깨끗함')
    raise SystemExit(0)

for eid in unresolved:
    now_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    summary = (
        f'RESOLVED | Role: $ROLE_NAME | By: @rehearsal-reset | '
        f'Action: Manual Reset (script) → policy detached, no session revoke needed | At: {now_iso}'
    )
    msg = json.dumps({'event_id': eid, 'summary': summary})
    ts_ms = str(int(time.time() * 1000))
    subprocess.run(
        ['aws', 'logs', 'put-log-events', '--log-group-name', LOG_GROUP,
         '--log-stream-name', STREAM, '--region', REGION,
         '--log-events', f'timestamp={ts_ms},message={json.dumps(msg)}'],
        capture_output=True, text=True,
    )
    print(f'  resolved: {eid}')
"

echo "▶ ${DEMO_USERNAME}의 revoke-session Deny 정책을 8개 Role에서 전부 제거"
for role in "${ALL_ROLES[@]}"; do
  aws iam delete-role-policy --role-name "$role" \
    --policy-name "revoke-session-${DEMO_USERNAME}" --region "$REGION" 2>/dev/null \
    && echo "  removed from: $role" || true
done

echo "▶ ${DEMO_USERNAME} Keycloak 계정 재활성화 (Lock & Revoke로 비활성화됐을 수 있음)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCLOAK_IID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=demo-project-dev-keycloak-poc" "Name=instance-state-name,Values=running" \
  --region "$REGION" --query 'Reservations[0].Instances[0].InstanceId' --output text)

RE_ENABLE_SCRIPT=$(mktemp)
cat > "$RE_ENABLE_SCRIPT" << EOF
ADMIN_PASSWORD=\$(aws ssm get-parameter --name /keycloak/demo-project-dev/admin-password --with-decryption --region ${REGION} --query Parameter.Value --output text)
docker exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password "\$ADMIN_PASSWORD" >/dev/null 2>&1
USER_ID=\$(docker exec keycloak /opt/keycloak/bin/kcadm.sh get users -r corp -q username=${DEMO_USERNAME} --fields id --format csv --noquotes | tail -1)
if [ -z "\$USER_ID" ]; then
  echo "  Keycloak에 ${DEMO_USERNAME} 계정을 못 찾음"
else
  docker exec keycloak /opt/keycloak/bin/kcadm.sh update "users/\$USER_ID" -r corp -s enabled=true
  docker exec keycloak /opt/keycloak/bin/kcadm.sh get users -r corp -q username=${DEMO_USERNAME} --fields username,enabled
fi
EOF
bash "$SCRIPT_DIR/tf-run-ssm-script.sh" "$KEYCLOAK_IID" "$REGION" "$RE_ENABLE_SCRIPT"
rm -f "$RE_ENABLE_SCRIPT"

echo "▶ 최종 확인"
aws iam list-attached-role-policies --role-name "$ROLE_NAME" --region "$REGION"
echo "Clean Ready State 완료."
