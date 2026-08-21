"""
NIST 800-207 tenet 6("진행 중인 통신에서 신뢰를 계속 재평가")의 "진행 중 세션 강제
종료" 부분을 구현. Security Hub Custom Action으로 사람이 트리거한다(파괴적/
서비스영향 조치라 자동 실행 안 함 - ADR-005 결정 5).

세 가지를 동시에 한다:
  1. AWS 쪽: 지정된 사람(RoleSessionName)이 assume한 세션만 정밀 차단하는 Deny
     정책을 8개 Role 전부에 붙임(aws:userid 조건으로 그 사람 세션만 타겟팅 -
     같은 Role을 쓰는 다른 사람은 영향 없음). 단, 이 조건(DateLessThan
     aws:TokenIssueTime)의 태생적 한계로 "이미 발급된 세션"만 막히고, 대상자가
     비밀번호/OTP로 다시 로그인해서 새 토큰을 받으면 발급 시각이 그 이후라
     이 조건에 안 걸려서 다시 쓸 수 있다 - 그래서 2번이 필요하다.
  2. Keycloak 쪽: 그 사람의 Keycloak SSO 세션을 강제 로그아웃시킨다(활성
     세션 무효화 - Pomerium도 다음 재검증 시 이걸 감지해서 다시 로그인 요구).
  3. Keycloak 쪽: 계정 자체를 **비활성화**(enabled=false)한다 - 2번(로그아웃)만으로는
     비밀번호/OTP를 여전히 알고 있는 사람이 즉시 재로그인할 수 있어서(1번의
     한계와 맞물려 사실상 재로그인하면 다시 쓸 수 있게 됨), 진짜 "계정 잠금"이
     되려면 재인증 자체를 막아야 한다. 관리자가 Keycloak 콘솔에서 다시
     enabled=true로 되돌리기 전까지는 맞는 비밀번호/OTP를 넣어도 로그인 자체가
     거부된다.

⚠️ AWS 공식 문서에 명시된 한계: 정책 반영에 최대 몇 분이 걸릴 수 있어 완전한
"즉시"는 아닙니다. 그리고 대상자가 이미 진행 중이던 작업은 유실될 수 있습니다
(AWS 공식 경고 문구 그대로).
"""
import boto3
import json
import os
import ssl
import time
import urllib.parse
import urllib.request

# Keycloak은 이 프로젝트 전체에서 자체서명 인증서를 쓴다(PoC 전용,
# Pomerium/data.http 쪽도 동일하게 검증을 건너뜀) - 기본 SSL 검증을 켠 채로
# 두면 CERTIFICATE_VERIFY_FAILED로 매번 실패한다.
_INSECURE_SSL_CONTEXT = ssl.create_default_context()
_INSECURE_SSL_CONTEXT.check_hostname = False
_INSECURE_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

iam = boto3.client("iam")
secrets_client = boto3.client("secretsmanager") if os.environ.get("SLACK_SECRET_ARN") else None
ssm = boto3.client("ssm")
sns = boto3.client("sns")

REGION = os.environ["AWS_REGION"]
NAME_PREFIX = os.environ["NAME_PREFIX"]
KEYCLOAK_HOST = os.environ["KEYCLOAK_HOST"]
REALM_NAME = os.environ["REALM_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ROLE_NAMES = json.loads(os.environ["ROLE_NAMES_JSON"])  # 8개 Role 이름 리스트


def _revoke_aws_sessions(username: str):
    """8개 Role 전부에 이 사람 세션만 정밀 차단하는 Deny 정책을 붙인다."""
    policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "RevokeSpecificUserSession",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "StringLike": {"aws:userid": f"*:{username}"},
                "DateLessThan": {"aws:TokenIssueTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            },
        }],
    })

    revoked_roles = []
    for role_name in ROLE_NAMES:
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=f"revoke-session-{username}",
                PolicyDocument=policy_document,
            )
            revoked_roles.append(role_name)
        except iam.exceptions.NoSuchEntityException:
            continue  # 이 Role은 애초에 이 사람이 쓸 일이 없었을 수 있음
    return revoked_roles


def _get_keycloak_admin_token() -> str:
    admin_password = ssm.get_parameter(
        Name=f"/keycloak/{NAME_PREFIX}/admin-password", WithDecryption=True
    )["Parameter"]["Value"]

    # openssl rand -base64로 생성되는 admin 비밀번호엔 "+"가 섞일 수 있는데,
    # form 본문을 f-string으로 직접 조립하면 "+"가 공백으로 해석돼 인증이
    # 실패한다(실측으로 발견 - TROUBLESHOOTING.md 참고). urlencode로 조립.
    data = urllib.parse.urlencode({
        "client_id": "admin-cli",
        "grant_type": "password",
        "username": "admin",
        "password": admin_password,
    }).encode()
    req = urllib.request.Request(
        f"https://{KEYCLOAK_HOST}/realms/master/protocol/openid-connect/token",
        data=data, method="POST",
    )
    with urllib.request.urlopen(req, context=_INSECURE_SSL_CONTEXT) as resp:
        return json.loads(resp.read())["access_token"]


def _get_keycloak_user_id(username: str, admin_token: str) -> str | None:
    headers = {"Authorization": f"Bearer {admin_token}"}
    req = urllib.request.Request(
        f"https://{KEYCLOAK_HOST}/admin/realms/{REALM_NAME}/users?username={username}&exact=true",
        headers=headers,
    )
    with urllib.request.urlopen(req, context=_INSECURE_SSL_CONTEXT) as resp:
        users = json.loads(resp.read())
    return users[0]["id"] if users else None


def _logout_keycloak_user(user_id: str, admin_token: str):
    headers = {"Authorization": f"Bearer {admin_token}"}
    # 강제 로그아웃 (모든 활성 세션 무효화) - 계정 자체는 아직 살아있어서
    # 이것만으로는 비밀번호/OTP를 아는 사람이 바로 재로그인할 수 있다.
    req = urllib.request.Request(
        f"https://{KEYCLOAK_HOST}/admin/realms/{REALM_NAME}/users/{user_id}/logout",
        headers=headers, method="POST",
    )
    urllib.request.urlopen(req, context=_INSECURE_SSL_CONTEXT)


def _disable_keycloak_user(user_id: str, admin_token: str):
    # enabled=false - 이제 맞는 비밀번호/OTP를 넣어도 로그인 자체가 거부된다.
    # 관리자가 Keycloak 콘솔/kcadm.sh로 enabled=true 되돌리기 전까지 유지.
    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}
    req = urllib.request.Request(
        f"https://{KEYCLOAK_HOST}/admin/realms/{REALM_NAME}/users/{user_id}",
        data=json.dumps({"enabled": False}).encode("utf-8"),
        headers=headers, method="PUT",
    )
    urllib.request.urlopen(req, context=_INSECURE_SSL_CONTEXT)


def _extract_username(event: dict) -> str:
    # 수동 테스트/Slack 명령 경유
    if "username" in event:
        return event["username"]
    # Security Hub Custom Action 경유 - finding의 RoleSessionName 필드에서 추출
    try:
        finding = event["detail"]["findings"][0]
        return finding["Resources"][0]["Details"]["AwsIamRole"]["RoleSessionName"]  # 실제 필드 경로 재확인 필요
    except (KeyError, IndexError):
        raise ValueError("username을 이벤트에서 추출하지 못했습니다. {'username': '...'} 형태로 수동 재호출하세요.")


def handler(event, context):
    username = _extract_username(event)

    revoked_roles = _revoke_aws_sessions(username)

    keycloak_logged_out = False
    keycloak_disabled = False
    try:
        admin_token = _get_keycloak_admin_token()
        user_id = _get_keycloak_user_id(username, admin_token)
        if user_id:
            _logout_keycloak_user(user_id, admin_token)
            keycloak_logged_out = True
            _disable_keycloak_user(user_id, admin_token)
            keycloak_disabled = True
    except Exception as e:
        keycloak_logged_out = f"실패: {e}"

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"🚨 세션 강제 종료: {username}",
        Message=(
            f"대상: {username}\n"
            f"AWS 세션 차단 완료 Role: {', '.join(revoked_roles) if revoked_roles else '없음'}\n"
            f"Keycloak 로그아웃: {keycloak_logged_out}\n"
            f"Keycloak 계정 비활성화: {keycloak_disabled} (관리자가 다시 활성화하기 전까지 재로그인 불가)\n"
            f"참고: 정책 반영까지 최대 몇 분 소요될 수 있음(AWS 공식 안내)."
        ),
    )

    return {
        "statusCode": 200,
        "username": username,
        "revoked_roles": revoked_roles,
        "keycloak_logged_out": keycloak_logged_out,
        "keycloak_disabled": keycloak_disabled,
    }
