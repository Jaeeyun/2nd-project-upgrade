"""
Security Hub CRITICAL/HIGH finding을 받아서 컨텍스트를 붙여 Slack으로 보낸다.
"""
import json
import os
import time
import urllib.parse
import urllib.request
import boto3

cloudtrail = boto3.client("cloudtrail")
dynamodb = boto3.client("dynamodb")
secrets_client = boto3.client("secretsmanager")
logs_client = boto3.client("logs")  # <-- [추가] CloudWatch Logs 클라이언트

DEDUP_TABLE_NAME = os.environ["DEDUP_TABLE_NAME"]
SLACK_SECRET_ARN = os.environ["SLACK_SECRET_ARN"]
SLACK_CHANNEL = os.environ["SLACK_CHANNEL"]
AWS_ACCOUNT_ID = os.environ["AWS_ACCOUNT_ID"]
AWS_REGION = os.environ["AWS_REGION"]
DEDUP_TTL_HOURS = int(os.environ.get("DEDUP_TTL_HOURS", "24"))
CLOUDTRAIL_LOOKBACK_HOURS = int(os.environ.get("CLOUDTRAIL_LOOKBACK_HOURS", "48"))
CSPM_EXCEPTION_LOG_GROUP = os.environ["CSPM_EXCEPTION_LOG_GROUP"]  # <-- [추가] 로그 그룹 환경변수

_SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠"}


def _get_bot_token() -> str:
    # Incoming Webhook 대신 28-ciem-key-exception-flow.tf의 Bot Token을 그대로
    # 재사용한다 - 예외등록 콜백(ciem-key-exception-callback.py)이 나중에
    # chat.update로 이 메시지를 수정하려면, "메시지를 올린 봇"과 "수정하려는
    # 봇"이 반드시 같은 Slack App(같은 bot_id)이어야 하기 때문이다. Incoming
    # Webhook으로 올린 메시지는 별도 App/bot_id로 취급돼서 다른 Bot Token으로는
    # 절대 chat.update가 안 먹는다(라이브로 확인함 - auth.test의 bot_id가
    # Webhook 메시지의 bot_id와 달랐음).
    secret = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
    return json.loads(secret["SecretString"])["bot_token"]


def _is_duplicate(finding_id: str) -> bool:
    now = int(time.time())
    resp = dynamodb.get_item(
        TableName=DEDUP_TABLE_NAME,
        Key={"finding_id": {"S": finding_id}},
    )
    item = resp.get("Item")
    if item and int(item["expires_at"]["N"]) > now:
        return True

    dynamodb.put_item(
        TableName=DEDUP_TABLE_NAME,
        Item={
            "finding_id": {"S": finding_id},
            "expires_at": {"N": str(now + DEDUP_TTL_HOURS * 3600)},
            "sent_at": {"N": str(now)},
        },
    )
    return False


def _extract_resource_name(resource: dict) -> str:
    resource_id = resource.get("Id", "")
    if resource_id.startswith("arn:"):
        return resource_id.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
    return resource_id


def _lookup_actor(resource_name: str) -> dict | None:
    if not resource_name:
        return None
    end_time = time.time()
    start_time = end_time - CLOUDTRAIL_LOOKBACK_HOURS * 3600
    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_name}],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=1,
        )
    except Exception as exc:
        return {"error": str(exc)}

    events = resp.get("Events", [])
    if not events:
        return None

    event = events[0]
    raw = json.loads(event.get("CloudTrailEvent", "{}"))
    user_identity = raw.get("userIdentity", {})
    actor = user_identity.get("arn") or user_identity.get("principalId") or user_identity.get("type", "unknown")
    return {
        "actor": actor,
        "source_ip": raw.get("sourceIPAddress", "unknown"),
        "event_name": event.get("EventName", "unknown"),
        "event_time": event.get("EventTime").isoformat() if hasattr(event.get("EventTime"), "isoformat") else str(event.get("EventTime")),
    }


def _build_logs_insights_query(resource_name: str) -> str:
    return (
        "fields @timestamp, userIdentity.arn, sourceIPAddress, eventName, requestParameters\n"
        f"| filter @message like /{resource_name}/\n"
        "| sort @timestamp desc\n"
        "| limit 20"
    )


def _security_hub_deep_link(finding_id: str, product_arn: str) -> str:
    # 콘솔에서 직접 이 finding을 검색해 결과 화면 URL을 받아 역산한 형식 -
    # selectedFindingId={ProductArn}/{FindingId}를 한 번만 URL 인코딩.
    # (예전 버전은 search= 파라미터에 검색창 내부 이스케이프 문법을 흉내내
    # 이중 인코딩했는데, 실제 콘솔 동작과 안 맞아 0건으로 나오는 문제가 있었음)
    selected = f"{product_arn}/{finding_id}"
    encoded = urllib.parse.quote(selected, safe="")
    return (
        f"https://{AWS_REGION}.console.aws.amazon.com/securityhub/home?region={AWS_REGION}"
        f"#/findings?selectedFindingId={encoded}"
    )


def _post_to_slack(bot_token: str, finding: dict, actor: dict | None, logs_query: str, deep_link: str, resource_name: str):
    severity_label = finding.get("Severity", {}).get("Label", "UNKNOWN")
    emoji = _SEVERITY_EMOJI.get(severity_label, "⚪")
    title = finding.get("Title", "(제목 없음)")
    resources = finding.get("Resources", [{}])
    resource_type = resources[0].get("Type", "unknown") if resources else "unknown"
    account_id = finding.get("AwsAccountId", AWS_ACCOUNT_ID)
    region = finding.get("Region", AWS_REGION)
    compliance_status = finding.get("Compliance", {}).get("Status", "unknown")

    if actor and "error" not in actor:
        actor_text = (
            f"*변경자:* `{actor['actor']}`\n"
            f"*발신 IP:* `{actor['source_ip']}`\n"
            f"*조치:* `{actor['event_name']}` (`{actor['event_time']}`)"
        )
    elif actor and "error" in actor:
        actor_text = f"CloudTrail 조회 실패: {actor['error']}"
    else:
        actor_text = f"최근 {CLOUDTRAIL_LOOKBACK_HOURS}시간 내 CloudTrail 이벤트 없음 (오래된 리소스이거나 이름 매칭 실패)"

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} [{severity_label}] {title}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*리소스 타입:*\n{resource_type}"},
                    {"type": "mrkdwn", "text": f"*리소스 이름:*\n`{resource_name}`"},
                    {"type": "mrkdwn", "text": f"*계정:*\n{account_id}"},
                    {"type": "mrkdwn", "text": f"*리전:*\n{region}"},
                    {"type": "mrkdwn", "text": f"*컴플라이언스:*\n{compliance_status}"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": actor_text}},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*CloudWatch Logs Insights 쿼리 (복사해서 붙여넣기):*\n```{logs_query}```"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Security Hub에서 보기"},
                        "url": deep_link,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🛑 위험 수용 / 예외 등록"},
                        "style": "danger",
                        "action_id": "open_suppress_modal",
                        "value": json.dumps({
                            "finding_id": finding.get("Id", ""),
                            "product_arn": finding.get("ProductArn", ""),
                            "resource_id": resource_name,
                        }),
                    },
                ],
            },
        ]
    }

    payload["channel"] = SLACK_CHANNEL
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {bot_token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    # chat.postMessage도 실패 시 HTTP 200 + ok=false로만 알려준다 - 조용히
    # 무시하면 원인 파악이 안 되니 반드시 로그에 남긴다.
    if not result.get("ok"):
        print(json.dumps({"warning": "slack chat.postMessage failed", "error": result.get("error"), "response": result}))


# <-- [추가] Slack 발송 감사 로그 기록 함수
def _log_alert_sent(finding_id: str, resource_name: str, severity: str, title: str, actor: str):
    record = {
        "eventType": "CSPM_ALERT_SENT",
        "findingId": finding_id,
        "resourceId": resource_name,
        "severity": severity,
        "title": title,
        "actor": actor,
    }
    log_stream = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        logs_client.create_log_stream(logGroupName=CSPM_EXCEPTION_LOG_GROUP, logStreamName=log_stream)
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass
    logs_client.put_log_events(
        logGroupName=CSPM_EXCEPTION_LOG_GROUP,
        logStreamName=log_stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": json.dumps(record)}],
    )


def handler(event, context):
    findings = event.get("detail", {}).get("findings", [])
    bot_token = None
    processed, skipped_dup = 0, 0

    for finding in findings:
        finding_id = finding.get("Id", "")
        if not finding_id:
            continue
        if _is_duplicate(finding_id):
            skipped_dup += 1
            continue

        resources = finding.get("Resources", [{}])
        resource_name = _extract_resource_name(resources[0]) if resources else ""
        actor_data = _lookup_actor(resource_name)
        actor_str = actor_data.get("actor", "unknown") if actor_data and "error" not in actor_data else "unknown"
        severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
        title = finding.get("Title", "(제목 없음)")

        logs_query = _build_logs_insights_query(resource_name)
        deep_link = _security_hub_deep_link(finding_id, finding.get("ProductArn", ""))

        if bot_token is None:
            bot_token = _get_bot_token()
        _post_to_slack(bot_token, finding, actor_data, logs_query, deep_link, resource_name)

        # <-- [추가] Slack 발송 직후 CloudWatch Logs에 CSPM_ALERT_SENT 이벤트 기록
        _log_alert_sent(finding_id, resource_name, severity, title, actor_str)
        processed += 1

    return {"statusCode": 200, "processed": processed, "skipped_duplicate": skipped_dup}