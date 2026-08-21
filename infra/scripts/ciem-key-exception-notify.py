"""
매월 IAM 사용자의 Access Key를 스캔해서, 90일 이상 미사용이거나 90일 이상 된
키를 찾는다. 그냥 삭제하지 않고, 그 키를 발급한 IAM User의 'Owner' 태그(이메일)를
찾아서 Slack에 "계속 필요함(예외 유지)" / "삭제해도 됨" 버튼이 달린 인터랙티브
메시지를 보낸다. 실제 처리(태그 갱신 또는 삭제)는 ciem-key-exception-callback.py가
사람이 버튼을 누른 뒤에 수행한다 - 자동 삭제 없음(ADR-005 결정 5, ADR-017 결정 2).

사전 조건: 정적 Access Key가 필요한 예외 IAM User에는 반드시 'Owner' 태그(이메일
값)를 붙여두세요. 없으면 이 스크립트가 "소유자 불명"으로 채널 전체에만 알립니다.
"""
import boto3
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

iam = boto3.client("iam")
secrets_client = boto3.client("secretsmanager")

UNUSED_THRESHOLD_DAYS = 90
SLACK_SECRET_ARN = os.environ["SLACK_SECRET_ARN"]
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "#cspm-findings")


def _get_slack_bot_token() -> str:
    secret = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
    return json.loads(secret["SecretString"])["bot_token"]


def _days_since(dt) -> int:
    if dt is None:
        return 99999  # 한 번도 안 쓰인 키는 무조건 대상
    return (datetime.now(timezone.utc) - dt).days


def _find_owner_email(username: str) -> str | None:
    tags = iam.list_user_tags(UserName=username).get("Tags", [])
    for t in tags:
        if t["Key"] == "Owner":
            return t["Value"]
    return None


def _post_slack_interactive(token: str, username: str, key_id: str, owner_email: str | None, age_days: int, last_used_days):
    owner_text = f"<mailto:{owner_email}|{owner_email}>" if owner_email else "⚠️ 소유자 불명(Owner 태그 없음)"
    last_used_text = "한 번도 사용 안 됨" if last_used_days == 99999 else f"{last_used_days}일 전"

    payload = {
        "channel": SLACK_CHANNEL,
        "text": f"미사용 Access Key 발견: {username}/{key_id}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*🔑 미사용 Access Key 발견*\n"
                        f"IAM User: `{username}`\nKey ID: `{key_id}`\n"
                        f"생성 후: {age_days}일 경과 / 마지막 사용: {last_used_text}\n"
                        f"소유자: {owner_text}\n\n"
                        f"ADR-017 결정 2에 따라 자동 삭제하지 않습니다. 아래에서 선택해주세요."
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ 계속 필요함 (예외 유지)"},
                        "style": "primary",
                        "action_id": "keep_access_key",
                        "value": json.dumps({"username": username, "key_id": key_id}),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🗑 삭제해도 됨"},
                        "style": "danger",
                        "action_id": "revoke_access_key",
                        "value": json.dumps({"username": username, "key_id": key_id}),
                        "confirm": {
                            "title": {"type": "plain_text", "text": "정말 삭제할까요?"},
                            "text": {"type": "plain_text", "text": f"{username}의 Access Key {key_id}를 즉시 비활성화+삭제합니다."},
                            "confirm": {"type": "plain_text", "text": "삭제"},
                            "deny": {"type": "plain_text", "text": "취소"},
                        },
                    },
                ],
            },
        ],
    }

    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        if not result.get("ok"):
            raise RuntimeError(f"Slack API 실패: {result}")


def handler(event, context):
    token = _get_slack_bot_token()
    checked = 0
    flagged = 0

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                checked += 1
                key_id = key["AccessKeyId"]
                age_days = _days_since(key["CreateDate"])

                last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                last_used_date = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                last_used_days = _days_since(last_used_date)

                if age_days < UNUSED_THRESHOLD_DAYS and last_used_days < UNUSED_THRESHOLD_DAYS:
                    continue  # 정상 범위, 스킵

                owner_email = _find_owner_email(username)
                flagged += 1
                _post_slack_interactive(token, username, key_id, owner_email, age_days, last_used_days)

    return {"statusCode": 200, "checked": checked, "flagged": flagged}
