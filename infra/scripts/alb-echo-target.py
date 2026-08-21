"""
mTLS 내부 ALB 뒤에 붙는 더미 백엔드. 실제 HR 앱이 아직 배포되기 전, "Pomerium이
보낸 요청이 여기까지 실제로 도달하고, Pomerium이 붙인 인증 헤더(이메일 등)가
잘 전달되는지"를 확인하는 용도입니다. 나중에 실제 앱이 배포되면 이 Lambda
타겟 그룹을 그 앱의 Service로 바꾸면 됩니다.
"""
import json


def handler(event, context):
    headers = event.get("headers", {})

    # Pomerium이 실제로 어떤 헤더를 붙였는지 한눈에 보이게 그대로 반환
    pomerium_headers = {k: v for k, v in headers.items() if k.lower().startswith("x-pomerium")}

    body = {
        "message": "mTLS ALB 뒤 echo 백엔드에 도달했습니다.",
        "pomerium_headers": pomerium_headers,
        "all_headers": headers,
        "path": event.get("path", "/"),
        "method": event.get("httpMethod", "GET"),
    }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body, ensure_ascii=False, indent=2),
    }
