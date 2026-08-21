#!/usr/bin/env bash
# =============================================================================
# Grafana 알림 규칙 프로비저닝 - RDS 권한 드리프트 자동 REVOKE를 Slack으로
# =============================================================================
# scripts/rds-view-permission-check.py는 더 이상 SNS로 직접 알림을 보내지
# 않는다(VPC 안 Lambda가 SNS까지 나가려면 443 아웃바운드가 더 필요했고,
# 실제로 빠뜨려서 sns.publish()가 타임아웃나는 문제를 겪었음 -
# TROUBLESHOOTING.md 참고). 대신 CloudWatch Logs에 구조화된 한 줄만 남기고,
# 이 스크립트가 만드는 Grafana 알림 규칙이 그 로그를 감시해서 Slack으로
# 알린다 - 이러면 그 Lambda의 보안그룹은 RDS(5432) 외에는 아무것도 열
# 필요가 없다.
#
# 사전 조건: grafana-dashboard-setup.sh와 동일(CloudWatch 데이터소스가 이미
# 프로비저닝되어 있어야 함). 멱등: 같은 UID로 PUT하면 있으면 갱신, 없으면
# 생성.
set -euo pipefail
cd "$(dirname "$0")/.."

GRAFANA_ENDPOINT="${GRAFANA_ENDPOINT:-$(terraform output -raw grafana_workspace_endpoint)}"
GRAFANA_URL="https://${GRAFANA_ENDPOINT}"
KEYCLOAK_ENDPOINT="${KEYCLOAK_ENDPOINT:-$(terraform output -raw keycloak_alb_dns_name)}"
KEYCLOAK_USER="${KEYCLOAK_USER:?KEYCLOAK_USER 필요(예: test-ops-lead, Grafana Admin 역할 매핑된 계정)}"
KEYCLOAK_PASSWORD="${KEYCLOAK_PASSWORD:?KEYCLOAK_PASSWORD 필요}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
SLACK_CHANNEL="${SLACK_CHANNEL:-#cspm-findings}"
CLOUDWATCH_DATASOURCE_UID="${CLOUDWATCH_DATASOURCE_UID:?grafana-dashboard-setup.sh 실행 후 나온 CW_UID 값을 넣으세요}"
JAR="$(mktemp)"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

echo "▶ SAML 로그인으로 세션 확보"
REDIRECT=$(curl -sk -A "$UA" -c "$JAR" -D - -o /dev/null --max-time 10 "$GRAFANA_URL/login/saml" | grep -i "^location:" | sed 's/location: //I' | tr -d '\r')
KC_LOGIN_PAGE=$(mktemp)
curl -sk -A "$UA" -b "$JAR" -c "$JAR" --max-time 10 "$REDIRECT" -o "$KC_LOGIN_PAGE"
FORM_ACTION=$(grep -o 'action="[^"]*"' "$KC_LOGIN_PAGE" | head -1 | sed 's/action="//;s/"$//' | sed 's/\&amp;/\&/g')
LOGIN_RESP=$(mktemp)
curl -sk -A "$UA" -b "$JAR" -c "$JAR" --max-time 15 \
  --data-urlencode "username=$KEYCLOAK_USER" \
  --data-urlencode "password=$KEYCLOAK_PASSWORD" \
  --data-urlencode "credentialId=" \
  "$FORM_ACTION" -o "$LOGIN_RESP"
python3 -c "
import re
html = open('$LOGIN_RESP').read()
sr = re.search(r'name=\"SAMLResponse\" value=\"([^\"]*)\"', html)
rs = re.search(r'name=\"RelayState\" value=\"([^\"]*)\"', html)
open('/tmp/ga_saml_response.txt','w').write(sr.group(1))
open('/tmp/ga_relay_state.txt','w').write(rs.group(1))
"
curl -sk -A "$UA" -b "$JAR" -c "$JAR" --max-time 15 \
  --data-urlencode "SAMLResponse@/tmp/ga_saml_response.txt" \
  --data-urlencode "RelayState@/tmp/ga_relay_state.txt" \
  "$GRAFANA_URL/saml/acs" -o /dev/null
rm -f /tmp/ga_saml_response.txt /tmp/ga_relay_state.txt "$KC_LOGIN_PAGE" "$LOGIN_RESP"

echo "▶ 서비스 계정 + 토큰 확보(멱등 - 이미 있으면 재사용)"
SA_ID=$(curl -sk -b "$JAR" "$GRAFANA_URL/api/serviceaccounts/search?query=terraform-automation" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['serviceAccounts'][0]['id'] if d['serviceAccounts'] else '')")
if [ -z "$SA_ID" ]; then
  SA_ID=$(curl -sk -b "$JAR" -X POST "$GRAFANA_URL/api/serviceaccounts" -H "Content-Type: application/json" \
    -d '{"name":"terraform-automation","role":"Admin"}' | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
fi
TOKEN=$(curl -sk -b "$JAR" -X POST "$GRAFANA_URL/api/serviceaccounts/$SA_ID/tokens" -H "Content-Type: application/json" \
  -d '{"name":"alerting-setup-'"$(date +%s)"'","secondsToLive":3600}' | python3 -c "import json,sys; print(json.load(sys.stdin)['key'])")
auth() { curl -sk -H "Authorization: Bearer $TOKEN" "$@"; }

echo "▶ Slack Contact Point 생성(멱등 - 있으면 갱신)"
BOT_TOKEN=$(aws secretsmanager get-secret-value --secret-id "${NAME_PREFIX:-demo-project-dev}-slack-app-credentials" --query 'SecretString' --output text | python3 -c "import sys,json; print(json.load(sys.stdin)['bot_token'])")
EXISTING_CP=$(auth "$GRAFANA_URL/api/v1/provisioning/contact-points" | python3 -c "
import json,sys
for cp in json.load(sys.stdin):
    if cp['name']=='slack-rds-drift':
        print(cp['uid']); break
")
CP_BODY=$(python3 -c "
import json
print(json.dumps({
  'name': 'slack-rds-drift', 'type': 'slack',
  'settings': {'token': '$BOT_TOKEN', 'recipient': '$SLACK_CHANNEL'},
  'disableResolveMessage': False
}))
")
if [ -n "$EXISTING_CP" ]; then
  auth -X PUT "$GRAFANA_URL/api/v1/provisioning/contact-points/$EXISTING_CP" -H "Content-Type: application/json" -H "X-Disable-Provenance: true" -d "$CP_BODY" >/dev/null
else
  auth -X POST "$GRAFANA_URL/api/v1/provisioning/contact-points" -H "Content-Type: application/json" -H "X-Disable-Provenance: true" -d "$CP_BODY" >/dev/null
fi
echo "  contact point: slack-rds-drift → $SLACK_CHANNEL"

echo "▶ 알림용 폴더 확보(멱등)"
auth -X POST "$GRAFANA_URL/api/folders" -H "Content-Type: application/json" -d '{"title":"SOC Alerts","uid":"soc-alerts"}' >/dev/null 2>&1 || true

echo "▶ 알림 규칙 생성/갱신(멱등 - PUT은 있으면 갱신, 없으면 새로 만듦)"
RULE_BODY=$(python3 -c "
import json
body = {
  'uid': 'rds-perm-drift-revoked',
  'title': 'RDS 마스킹 뷰 우회 권한 자동 REVOKE 발생',
  'ruleGroup': 'rds-drift-checks',
  'folderUID': 'soc-alerts',
  'condition': 'C',
  'data': [
    {
      'refId': 'A', 'datasourceUid': '$CLOUDWATCH_DATASOURCE_UID', 'queryType': 'Logs',
      'relativeTimeRange': {'from': 300, 'to': 0},
      'model': {
        'region': '$AWS_REGION', 'queryMode': 'Logs',
        'logGroups': [{'accountId': '$AWS_ACCOUNT_ID', 'arn': 'arn:aws:logs:$AWS_REGION:$AWS_ACCOUNT_ID:log-group:/aws/lambda/${NAME_PREFIX:-demo-project-dev}-rds-view-permission-check:*', 'name': '/aws/lambda/${NAME_PREFIX:-demo-project-dev}-rds-view-permission-check'}],
        'statsGroups': [],
        'queryString': 'fields @timestamp, @message | filter @message like /RDS_PERMISSION_DRIFT_REVOKED/ | stats count() as driftCount',
        'refId': 'A'
      }
    },
    {
      'refId': 'C', 'datasourceUid': '__expr__', 'queryType': '',
      'relativeTimeRange': {'from': 300, 'to': 0},
      'model': {'type': 'threshold', 'expression': 'A', 'conditions': [{'evaluator': {'type': 'gt', 'params': [0]}}], 'refId': 'C'}
    }
  ],
  'noDataState': 'OK', 'execErrState': 'Error', 'for': '0s',
  'annotations': {'summary': 'RDS 원본 테이블에 대한 우회 권한이 발견되어 자동으로 REVOKE되었습니다.'},
  'labels': {'severity': 'warning'},
  'notification_settings': {'receiver': 'slack-rds-drift'}
}
print(json.dumps(body))
")
RULE_STATUS=$(auth -o /dev/null -w "%{http_code}" -X PUT "$GRAFANA_URL/api/v1/provisioning/alert-rules/rds-perm-drift-revoked" \
  -H "Content-Type: application/json" -H "X-Disable-Provenance: true" -d "$RULE_BODY")
if [ "$RULE_STATUS" = "404" ]; then
  auth -X POST "$GRAFANA_URL/api/v1/provisioning/alert-rules" -H "Content-Type: application/json" -H "X-Disable-Provenance: true" -d "$RULE_BODY" >/dev/null
fi
echo "  alert rule: rds-perm-drift-revoked (folder: SOC Alerts)"

rm -f "$JAR"
echo "GRAFANA_ALERTING_SETUP_DONE"
