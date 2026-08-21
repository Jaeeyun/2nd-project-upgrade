"""
매 N시간마다(기본 3시간 - 데모/테스트용 짧은 값, 아래 경고 참고) 지정된 SAML
Role 하나의 정책이 실제 CloudTrail 활동과 얼마나 다른지 IAM Access Analyzer
Policy Generation으로 분석한다. 차이(=최근 N시간 동안 안 쓰인 권한)가 있으면
Slack에 "적용/유지" 버튼과 함께 알리고, 실제 정책 교체는
ciem-key-exception-callback.py(Slack Interactivity URL이 앱 전체에 하나뿐이라
콜백을 이걸로 통합함, action_id로 구분)가 사람이 버튼을 눌러야만 실행한다
(ADR-005 결정 5, 100-SCENARIOS.md 82번 시나리오와 동일한 Human-in-the-Loop
원칙 - 발견은 자동, 실행은 사람 승인 후에만. 자동 삭제 없음).

⚠️ LOOKBACK_HOURS는 데모/테스트 목적의 짧은 값입니다(기본 3시간). 실제 운영
환경에서는 저빈도 정당 업무(분기별 작업 등)를 "미사용"으로 오탐하지 않도록
훨씬 긴 관찰 기간(최소 몇 주, 24-ciem-lambda.tf의 Unused Access 분석이 90일
기준을 쓰는 것과 같은 이유)을 쓰는 걸 강력히 권장합니다. 이 스크립트는 한 번
호출에 Role 하나만 처리한다 - 여러 Role을 한 Lambda 호출 안에서 순서대로
돌리면 Policy Generation 대기시간이 누적되어 Lambda 자체 타임아웃(최대 15분)에
걸릴 수 있어서, Role별로 별도 EventBridge 스케줄 호출로 나눴다
(36-ciem-boundary-drift-check.tf 참고).
"""
import boto3
import json
import os
import time
import urllib.request
from datetime import datetime, timedelta, timezone

iam = boto3.client("iam")
access_analyzer = boto3.client("accessanalyzer")
secrets_client = boto3.client("secretsmanager")
sts = boto3.client("sts")

REGION = os.environ["AWS_REGION"]
NAME_PREFIX = os.environ["NAME_PREFIX"]
CLOUDTRAIL_ARN = os.environ["CLOUDTRAIL_ARN"]
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "3"))
SLACK_SECRET_ARN = os.environ["SLACK_SECRET_ARN"]
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL", "#cspm-findings")
ACCESS_ANALYZER_ROLE_ARN = os.environ["ACCESS_ANALYZER_ROLE_ARN"]
POLICY_GENERATION_TIMEOUT_SECONDS = 420  # Lambda 타임아웃(600s로 설정 권장)보다 여유있게 짧게


def _get_slack_bot_token() -> str:
    secret = secrets_client.get_secret_value(SecretId=SLACK_SECRET_ARN)
    return json.loads(secret["SecretString"])["bot_token"]


def _current_role_actions(role_name: str) -> set:
    """현재 Role에 붙은 인라인 정책들의 Action을 전부 모아 집합으로."""
    actions = set()
    for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            action = stmt.get("Action", [])
            actions.update([action] if isinstance(action, str) else action)
    return actions


def _generated_policy_actions(job_id: str):
    resp = access_analyzer.get_generated_policy(jobId=job_id)
    policies = resp.get("generatedPolicyResult", {}).get("generatedPolicies", [])
    if not policies:
        return set(), None
    policy = json.loads(policies[0]["policy"])
    actions = set()
    for stmt in policy.get("Statement", []):
        action = stmt.get("Action", [])
        actions.update([action] if isinstance(action, str) else action)
    return actions, policy


def _start_policy_generation(role_arn: str, start_time: str, end_time: str) -> str:
    resp = access_analyzer.start_policy_generation(
        policyGenerationDetails={"principalArn": role_arn},
        cloudTrailDetails={
            "trails": [{"cloudTrailArn": CLOUDTRAIL_ARN, "allRegions": True}],
            "startTime": start_time,
            "endTime": end_time,
            "accessRole": ACCESS_ANALYZER_ROLE_ARN,
        },
    )
    return resp["jobId"]


def _wait_for_job(job_id: str) -> str:
    deadline = time.time() + POLICY_GENERATION_TIMEOUT_SECONDS
    while time.time() < deadline:
        status = access_analyzer.get_generated_policy(jobId=job_id)["jobDetails"]["status"]
        if status != "IN_PROGRESS":
            return status
        time.sleep(10)
    return "TIMED_OUT"


def _post_slack_interactive(token: str, role_name: str, role_arn: str, job_id: str, unused_actions: set, start_str: str, end_str: str):
    sorted_actions = sorted(unused_actions)
    unused_list = "\n".join(f"• `{a}`" for a in sorted_actions[:30])
    if len(sorted_actions) > 30:
        unused_list += f"\n... 외 {len(sorted_actions) - 30}건"

    payload = {
        "channel": SLACK_CHANNEL,
        "text": f"권한 드리프트 발견: {role_name}",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*🔍 최근 {LOOKBACK_HOURS}시간 미사용 권한 발견*\n"
                        f"Role: `{role_name}`\n"
                        f"분석 대상 기간: `{start_str}` ~ `{end_str}`\n"
                        f"(⚠️ 이 구간 이후의 활동은 이번 결과에 반영되지 않습니다 - 지금 막 쓴 권한이라도 "
                        f"버튼을 누르면 이 시점 기준 정책이 그대로 적용됩니다)\n"
                        f"이 구간 동안 CloudTrail에서 관찰되지 않은 권한:\n"
                        f"{unused_list}\n\n"
                        f"⚠️ 짧은 관찰 기간(데모/테스트용)이라 저빈도 정당 업무가 여기 섞여 "
                        f"있을 수 있습니다. 자동으로 빼지 않습니다 - 아래에서 선택해주세요."
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ 이 권한들 제거 (최소화 적용)"},
                        "style": "primary",
                        "action_id": "apply_reduced_policy",
                        "value": json.dumps({"role_name": role_name, "role_arn": role_arn, "job_id": job_id}),
                        "confirm": {
                            "title": {"type": "plain_text", "text": "정말 적용할까요?"},
                            "text": {"type": "plain_text", "text": f"{role_name}의 정책을 위 목록만큼 줄인 정책으로 즉시 교체합니다."},
                            "confirm": {"type": "plain_text", "text": "적용"},
                            "deny": {"type": "plain_text", "text": "취소"},
                        },
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔒 그대로 유지 (오탐/저빈도 업무)"},
                        "action_id": "keep_current_policy",
                        "value": json.dumps({"role_name": role_name}),
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
    # EventBridge Scheduler가 role_suffix 하나를 담아서 호출한다(36번 tf 참고).
    # 수동 테스트 시엔 {"role_suffix": "ops-general"} 형태로 직접 호출 가능.
    role_suffix = event["role_suffix"]
    role_name = f"{NAME_PREFIX}-{role_suffix}"
    account_id = sts.get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    token = _get_slack_bot_token()
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # 촬영/디버깅 시 "지금 이 순간의 활동"과 "분석에 실제로 반영되는 활동"을
    # 헷갈리기 쉽다(분석 시작 시점 이후의 새 활동은 이번 결과에 반영 안 됨) -
    # 그래서 실제 분석 구간을 CloudWatch Logs에 명시적으로 남긴다.
    print(f"[{role_name}] 분석 대상 기간: {start_str} ~ {end_str} (최근 {LOOKBACK_HOURS}시간, 이 구간 이후의 활동은 이번 결과에 반영되지 않음)")

    current_actions = _current_role_actions(role_name)
    job_id = _start_policy_generation(role_arn, start_str, end_str)
    status = _wait_for_job(job_id)

    if status != "SUCCEEDED":
        print(f"[{role_name}] Policy Generation 실패/타임아웃: {status}")
        return {"statusCode": 200, "role": role_name, "result": f"job_{status.lower()}"}

    generated_actions, generated_policy = _generated_policy_actions(job_id)
    if generated_policy is None:
        print(f"[{role_name}] 관찰된 활동 없음 - 최근 {LOOKBACK_HOURS}시간 동안 이 Role이 전혀 사용되지 않음")
        return {"statusCode": 200, "role": role_name, "result": "no_activity_observed"}

    unused_actions = current_actions - generated_actions
    if not unused_actions:
        print(f"[{role_name}] 미사용 권한 없음")
        return {"statusCode": 200, "role": role_name, "result": "no_drift"}

    _post_slack_interactive(token, role_name, role_arn, job_id, unused_actions, start_str, end_str)
    return {"statusCode": 200, "role": role_name, "result": "flagged", "unused_count": len(unused_actions)}
