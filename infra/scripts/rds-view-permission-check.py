"""
RDS 마스킹 뷰 권한 드리프트 복구 Lambda. general_user_readonly/approver_readonly가
언제부터인가 employees/change_history 원본 테이블에 직접 GRANT를 받은 상태라면
(사람 실수, 또는 다른 자동화가 잘못 건드린 경우) 즉시 REVOKE로 되돌린다.
100-SCENARIOS.md의 76번 시나리오("파라미터 그룹/권한이 실수로 되돌아감")에 대응.

이 Lambda는 REVOKE를 실행할 수 있어야 하므로, 일반 조회용 IAM 역할
(general_user_readonly 등)이 아니라 별도의 `remediation_admin` DB 역할을 씁니다.
이 역할은 hr-data-masking-views.sql에서 마스터 계정이 미리 만들어야 합니다
(테이블 소유자이거나 그에 준하는 권한 필요).

알림은 이 Lambda가 직접 보내지 않는다(SNS 미사용) - DB(RDS) 안에서 REVOKE만
책임지고, "발견/복구했다"는 사실은 CloudWatch Logs에 구조화된 한 줄로만
남긴다. Slack 알림은 Grafana 알림 규칙(CloudWatch Logs Insights로 이 로그
그룹을 감시)이 담당한다 - scripts/grafana-alerting-setup.sh 참고. 이렇게
나누면 이 Lambda가 VPC 밖(SNS 등)으로 나갈 필요가 아예 없어져서 보안그룹을
RDS(5432) 외에는 더 열 필요가 없다(실제로 SNS 아웃바운드가 막혀 있어
sns.publish()가 타임아웃나던 문제를 근본적으로 없앤 설계).

⚠️ psycopg2는 Lambda 기본 런타임에 없어 Layer가 필요합니다. AWS 공식 Layer가
없어 커뮤니티 Layer(예: jetbridge/psycopg2-lambda-layer)를 쓰거나 직접 빌드해야
합니다. terraform 쪽에 layer ARN을 변수로 빼뒀으니, 실제 값은 apply 전에 채우세요.
"""
import json
import os
import psycopg2
import boto3

rds = boto3.client("rds")

DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ["DB_NAME"]
DB_USER = os.environ.get("DB_USER", "remediation_admin")
REGION = os.environ["AWS_REGION"]

WATCHED_TABLES = ["employees", "change_history"]
READONLY_ROLES = ["general_user_readonly", "approver_readonly"]


def _get_auth_token() -> str:
    return rds.generate_db_auth_token(
        DBHostname=DB_HOST, Port=DB_PORT, DBUsername=DB_USER, Region=REGION
    )


def handler(event, context):
    token = _get_auth_token()
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER,
        password=token, sslmode="require",
    )
    conn.autocommit = True
    drift_found = []

    try:
        with conn.cursor() as cur:
            for table in WATCHED_TABLES:
                # ANY(%s)로 파이썬 리스트를 넘기면 psycopg2가 배열로 어댑팅하는데,
                # 이 Lambda가 쓰는 커뮤니티 psycopg2 Layer 조합에서 실제로는 매칭이
                # 안 되는 걸 실측으로 확인했다(수동 psql로는 똑같은 쿼리가 정상
                # 동작해서 처음엔 발견하기 어려웠음) - 어떤 조합에서도 안정적으로
                # 동작하는 IN %s(튜플 어댑팅) 방식으로 바꿨다.
                cur.execute(
                    """
                    SELECT grantee, privilege_type
                    FROM information_schema.role_table_grants
                    WHERE table_name = %s AND grantee IN %s
                    """,
                    (table, tuple(READONLY_ROLES)),
                )
                rows = cur.fetchall()
                for grantee, privilege in rows:
                    drift_found.append((table, grantee, privilege))
                    cur.execute(f"REVOKE ALL ON {table} FROM {grantee};")

        # Grafana 알림 규칙이 CloudWatch Logs Insights로 이 한 줄을 감시한다
        # (scripts/grafana-alerting-setup.sh) - 사람이 읽기 좋은 텍스트가
        # 아니라 파싱하기 쉬운 구조로 남긴다.
        for table, grantee, privilege in drift_found:
            print(json.dumps({
                "event": "RDS_PERMISSION_DRIFT_REVOKED",
                "table": table,
                "grantee": grantee,
                "privilege": privilege,
            }))
        return {"statusCode": 200, "drift_count": len(drift_found)}
    finally:
        conn.close()
