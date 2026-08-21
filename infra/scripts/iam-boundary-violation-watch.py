"""
8개 SAML Role(12-iam-saml-roles.tf)은 인라인 정책 하나만 갖도록 설계돼 있어서
(ADR-019, Permission Boundary + 인라인 정책 단일 모델) 별도 관리형 정책이
붙는 경우가 원래 없다 - 즉 이 Role들에 AttachRolePolicy가 호출된다는 사실
자체가 이미 "설계된 경계 밖의 권한이 붙었다"는 이상 징후다. 정책 종류별로
위험도를 채점하지 않고, "원래 아무것도 안 붙어야 하는데 뭔가 붙었다" 그
자체를 위반으로 본다(EXPECTED_MANAGED_POLICY_ARNS에 예외를 추가하면 특정
정책만 정상으로 취급 가능 - 기본은 빈 목록).

이 Lambda는 위반 "발생" 시점에 status=UNRESOLVED 로그 한 줄만 남긴다.
"해결" 시점의 status=RESOLVED 로그는 ciem-key-exception-callback.py가
(사람이 Slack 버튼을 눌렀을 때) 같은 event_id로 별도로 남긴다 - 두 로그가
event_id로 짝지어지는 덕분에 Grafana가 "미해결 목록(status의 마지막 값이
UNRESOLVED인 event_id만)"과 "해결 타임라인(RESOLVED 로그 전체)"을 로그
하나의 소스에서 별도 패널로 분리해서 보여줄 수 있다.

event_id는 새로 안 만들고 CloudTrail이 API 호출마다 이미 발급하는 고유
eventID를 그대로 쓴다(EventBridge가 detail.eventID로 그대로 넘겨줌) - 발생과
해결 두 로그가 자연스럽게 같은 키로 묶인다.

EventBridge가 CloudTrail의 AttachRolePolicy 관리 이벤트를 실시간으로(계정
기본 이벤트 버스 - 별도 Trail-to-EventBridge 설정 불필요, API 호출 후 보통
몇 초 내 도착) 이 Lambda에 전달하면:
  1. status=UNRESOLVED 로그 한 줄을 CloudWatch Logs에 구조화된 JSON으로 남긴다.
  2. Slack에 "🔒 잠금 & 회수" / "⚠️ 예외 승인" 두 버튼과 함께 알린다. 실제
     조치(잠금)는 여기서 구현하지 않고 이미 있는 session-revoke Lambda를
     그대로 재사용한다(ciem-key-exception-callback.py 참고).

⚠️ 이 Lambda 자체는 us-east-1에서 실행된다(44-iam-boundary-violation-watch.tf
참고 - IAM은 글로벌 서비스라 이 이벤트가 항상 us-east-1 기본 이벤트 버스로만
전달되는 걸 실측으로 확인함, ap-northeast-2엔 전혀 안 옴). 로그그룹/Secret은
그대로 ap-northeast-2에 있으므로 아래 boto3 클라이언트는 region_name을
명시적으로 지정한다 - 안 그러면 Lambda 실행 리전(us-east-1)의 기본값을 타서
엉뚱한 리전에 로그를 쓰려다 실패한다.
"""
import boto3
import json
import os
import time
import urllib.request

logs_client = boto3.client("logs", region_name="ap-northeast-2")
secrets_client = boto3.client("secretsmanager", region_name="ap-northeast-2")

LOG_GROUP_NAME = os.environ["LOG_GROUP_NAME"]
SLACK_SECRET_ARN = os.environ["SLACK_SECRET_ARN"]
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "#cspm-findings")
NAME_PREFIX = os.environ["NAME_PREFIX"]
EXPECTED_MANAGED_POLICY_ARNS = set(filter(None, os.environ.get("EXPECTED_MANAGED_POLICY_ARNS", "").split(",")))


def _get_slack_bot_token() -> str:
    secret = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
    return json.loads(secret["SecretString"])["bot_token"]


def _extract_username(user_identity: dict) -> str:
    # SAML로 assume한 세션은 arn:aws:sts::ACCOUNT:assumed-role/ROLE/ROLE_SESSION_NAME
    # 형태이고 RoleSessionName이 곧 Keycloak 사용자명이다(session-revoke.py와 동일 규칙).
    arn = user_identity.get("arn", "")
    if "assumed-role" in arn:
        return arn.rsplit("/", 1)[-1]
    return user_identity.get("principalId", "unknown")


def _role_owner_username(role_name: str) -> str:
    # ⚠️ "누가 이 정책을 붙였는지"(attached_by, CloudTrail userIdentity)와
    # "이 Role을 원래 정상적으로 쓰던 사람"은 다를 수 있다 - 예를 들어 root/관리자가
    # dev-general Role에 실수로/악의적으로 AdministratorAccess를 붙였다면,
    # attached_by는 root지만 정작 잠가야 할 대상은 그 권한을 실제로 갖고
    # 활동하게 될 dev-general의 정상 사용자(test-dev-general)다. 이 프로젝트의
    # 데모 계정은 keycloak-bootstrap.sh.tpl에서 "test-<role-suffix>" 규칙으로
    # 만들어지므로(create_test_user_in_group), Role 이름에서 그대로 역산한다.
    suffix = role_name[len(NAME_PREFIX) + 1:] if role_name.startswith(f"{NAME_PREFIX}-") else role_name
    return f"test-{suffix}"


def _log_unresolved(event_id: str, target_role: str, violation_policy: str, attached_by: str, target_username: str):
    # ⚠️ CloudWatch Logs Insights의 "stats latest(a) as a, latest(b) as b by k"는
    # 여러 개의 latest() 별칭을 한 stats 절에 같이 쓰면 마지막 하나만 남기고
    # 앞선 것들을 조용히 버린다(실측으로 확인된 CWLI 동작 - 문서화 안 돼
    # 있음). event_id별 "가장 최근 상태"를 안정적으로 구하려면 by 그룹당
    # latest() 하나만 써야 해서, role/policy/누가/상태를 전부 문자열 하나
    # (summary)에 합쳐서 그 필드 하나만 latest()로 집계한다. Grafana
    # 패널에서 UNRESOLVED로 시작하는지(정규식)만 보고 색을 입힌다.
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    summary = (
        f"UNRESOLVED | Role: {target_role} | Policy: {violation_policy.rsplit('/', 1)[-1]} "
        f"| AttachedBy: {attached_by} | LockTarget: {target_username} | At: {now_iso}"
    )
    log_stream = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        logs_client.create_log_stream(logGroupName=LOG_GROUP_NAME, logStreamName=log_stream)
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass
    logs_client.put_log_events(
        logGroupName=LOG_GROUP_NAME,
        logStreamName=log_stream,
        logEvents=[{
            "timestamp": int(time.time() * 1000),
            "message": json.dumps({"event_id": event_id, "summary": summary}),
        }],
    )


def _post_slack_alert(token: str, event_id: str, role_name: str, policy_arn: str, attached_by: str, target_username: str):
    policy_name = policy_arn.rsplit("/", 1)[-1]
    button_value = json.dumps({
        "event_id": event_id,
        "username": target_username,
        "role_name": role_name,
        "policy_arn": policy_arn,
    })
    payload = {
        "channel": SLACK_CHANNEL,
        "text": f"🚨 [SECURITY ALERT] Unauthorized IAM Policy Attached - {role_name}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*🚨 [SECURITY ALERT] Unauthorized IAM Policy Attached*\n\n"
                        f"• 대상 Role: `{role_name}`\n"
                        f"• 위반 Policy: `{policy_name}`\n"
                        f"• 정책을 붙인 계정: `{attached_by}`\n"
                        f"• 잠금 대상(이 Role의 정상 사용자): `{target_username}`\n"
                        f"• 상태: 🔴 미해결 (Unresolved)\n\n"
                        f"이 Role은 원래 인라인 정책 하나만 쓰도록 설계돼 있어서, "
                        f"관리형 정책이 붙는 것 자체가 정상 범위를 벗어난 상태입니다.\n"
                        f"아래 조치 버튼 중 하나를 선택하세요:"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔒 세션 잠금 & 권한 회수 (Lock & Revoke)"},
                        "style": "danger",
                        "action_id": "lock_account_risk",
                        "value": button_value,
                        "confirm": {
                            "title": {"type": "plain_text", "text": "정말 잠글까요?"},
                            "text": {"type": "plain_text", "text": f"{target_username}의 AWS 세션 전체와 Keycloak SSO 세션을 즉시 강제 종료합니다."},
                            "confirm": {"type": "plain_text", "text": "잠금"},
                            "deny": {"type": "plain_text", "text": "취소"},
                        },
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⚠️ 예외 승인 (Approve)"},
                        "action_id": "approve_exception_risk",
                        "value": button_value,
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
    # EventBridge가 CloudTrail "AttachRolePolicy" 관리 이벤트를 그대로 넘긴다
    # (44-iam-boundary-violation-watch.tf의 event_pattern으로 8개 Role만 필터링됨).
    detail = event["detail"]
    event_id = detail["eventID"]  # CloudTrail이 API 호출마다 발급하는 고유 ID - 해결 로그와 짝짓는 키
    request_params = detail["requestParameters"]
    role_name = request_params["roleName"]
    policy_arn = request_params["policyArn"]
    attached_by = _extract_username(detail.get("userIdentity", {}))
    target_username = _role_owner_username(role_name)

    if policy_arn in EXPECTED_MANAGED_POLICY_ARNS:
        return {"statusCode": 200, "result": "in_boundary", "role": role_name}

    _log_unresolved(event_id, role_name, policy_arn, attached_by, target_username)
    token = _get_slack_bot_token()
    _post_slack_alert(token, event_id, role_name, policy_arn, attached_by, target_username)
    return {
        "statusCode": 200, "result": "violation_alerted", "event_id": event_id,
        "role": role_name, "attached_by": attached_by, "target_username": target_username,
    }
