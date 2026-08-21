import datetime
import json
import os
import time
import boto3

securityhub = boto3.client("securityhub")
logs_client = boto3.client("logs")

CSPM_EXCEPTION_LOG_GROUP = os.environ["CSPM_EXCEPTION_LOG_GROUP"]
DUE_SOON_THRESHOLD_DAYS = int(os.environ.get("DUE_SOON_THRESHOLD_DAYS", "3"))


def _get_active_exceptions() -> list:
    """최근 90일 내 등록된 예외 중 아직 RECORDED 상태(CLOSED 안 된)인 것만 조회.

    dedup 다음에 filter를 이어붙이면 CloudWatch Logs Insights가
    MalformedQueryException을 낸다(dedup 뒤에는 filter를 못 붙임 - 라이브로
    확인함). 그래서 stats latest(field) by key 패턴으로 대체한다 - Grafana
    쪽 대시보드 패널(grafana-cspm-interactive-dashboard.json)에 쓴 것과
    동일한 패턴.

    별칭(as 뒤 이름)은 반드시 원본 필드명과 달라야 한다 - latest(x) as x처럼
    원본과 완전히 같은 이름으로 별칭을 주면 CWLI가 에러 없이 그 필드만 조용히
    빈 값으로 반환한다(라이브로 확인함, 대소문자만 다르면 안전).
    """
    query = (
        "fields eventType, findingId, productArn, resourceId, reviewDate, "
        "ticketRef, approvedBy, reasonType, rationale\n"
        "| filter eventType in ['CSPM_EXCEPTION_RECORDED', 'CSPM_EXCEPTION_CLOSED']\n"
        "| stats latest(eventType) as latestEventType, latest(productArn) as latestProductArn, "
        "latest(resourceId) as latestResourceId, latest(reviewDate) as latestReviewDate, "
        "latest(ticketRef) as latestTicketRef, latest(approvedBy) as latestApprovedBy, "
        "latest(reasonType) as latestReasonType, latest(rationale) as latestRationale by findingId\n"
        "| filter latestEventType = 'CSPM_EXCEPTION_RECORDED'\n"
        "| limit 200"
    )
    start_time = int(time.time() - 90 * 24 * 3600)
    end_time = int(time.time())

    resp = logs_client.start_query(
        logGroupName=CSPM_EXCEPTION_LOG_GROUP,
        startTime=start_time,
        endTime=end_time,
        queryString=query,
    )
    query_id = resp["queryId"]

    # 쿼리 완료 대기
    while True:
        res = logs_client.get_query_results(queryId=query_id)
        if res["status"] in ["Complete", "Failed", "Cancelled"]:
            break
        time.sleep(1)

    findings = []
    for row in res.get("results", []):
        row_dict = {f["field"]: f["value"] for f in row}
        if "findingId" not in row_dict:
            continue
        # CWLI 별칭(latestX)을 파이썬 쪽에서 쓰기 편한 원래 이름으로 되돌림
        findings.append({
            "findingId": row_dict["findingId"],
            "productArn": row_dict.get("latestProductArn", ""),
            "resourceId": row_dict.get("latestResourceId", ""),
            "reviewDate": row_dict.get("latestReviewDate", ""),
            "ticketRef": row_dict.get("latestTicketRef", ""),
            "approvedBy": row_dict.get("latestApprovedBy", ""),
            "reasonType": row_dict.get("latestReasonType", ""),
            "rationale": row_dict.get("latestRationale", ""),
        })
    return findings


def _fetch_findings_by_id(finding_ids: list) -> list:
    """Security Hub엔 BatchGetFindings API가 없다(라이브로 확인 - AttributeError로
    실패함) - Id를 EQUALS로 여러 개 나열한 GetFindings 필터로 대체한다(같은
    필터 키 안의 값들은 OR로 묶임). 필터 배열 크기 제한이 문서에 명확하지
    않아 50개씩 안전하게 나누고, 청크별로 NextToken 페이지네이션도 처리한다."""
    findings = []
    for i in range(0, len(finding_ids), 50):
        batch = finding_ids[i : i + 50]
        id_filters = [{"Value": fid, "Comparison": "EQUALS"} for fid in batch]
        next_token = None
        while True:
            kwargs = {"Filters": {"Id": id_filters}, "MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = securityhub.get_findings(**kwargs)
            findings.extend(resp.get("Findings", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
    return findings


def handler(event, context):
    active_exceptions = _get_active_exceptions()
    if not active_exceptions:
        return {"statusCode": 200, "checked": 0, "closed": 0, "dueSoon": 0}

    finding_ids = [item["findingId"] for item in active_exceptions if item.get("findingId")]
    # 조회에서 응답이 안 온 항목(삭제/전파 지연 등)은 안전하게 "아직
    # 열려있음"으로 취급 - 확인된 것만 명시적으로 제거한다.
    still_open_ids = set(finding_ids)

    closed_events = []
    for finding in _fetch_findings_by_id(finding_ids):
        finding_id = finding.get("Id")
        record_state = finding.get("RecordState")  # ACTIVE, ARCHIVED
        compliance = finding.get("Compliance", {}).get("Status")  # PASSED, FAILED

        # 리소스가 삭제되었거나(ARCHIVED), 취약점이 정상 해결된 경우(PASSED)
        if record_state == "ARCHIVED" or compliance == "PASSED":
            closed_events.append({
                "eventType": "CSPM_EXCEPTION_CLOSED",
                "findingId": finding_id,
                "closeReason": "RESOURCE_DELETED" if record_state == "ARCHIVED" else "COMPLIANCE_PASSED",
                "closedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            still_open_ids.discard(finding_id)

    # 재검토일 임박(DUE_SOON_THRESHOLD_DAYS일 이내, 이미 지난 것 포함) 판정 -
    # CWLI는 문자열 필드에 날짜 연산을 할 수 없어서(내장 함수가 @timestamp
    # 전용) 여기 Python 쪽에서 계산하고, 결과만 별도 이벤트로 남겨서
    # Grafana는 단순 eventType 필터만 하면 되게 한다.
    today = datetime.date.today()
    due_soon_events = []
    for item in active_exceptions:
        finding_id = item.get("findingId")
        if not finding_id or finding_id not in still_open_ids:
            continue  # 이번에 닫힌 걸로 확인된 건 임박 목록에서도 제외
        review_date_str = item.get("reviewDate")
        if not review_date_str:
            continue
        try:
            review_date = datetime.date.fromisoformat(review_date_str)
        except ValueError:
            continue
        days_remaining = (review_date - today).days
        if days_remaining <= DUE_SOON_THRESHOLD_DAYS:
            due_soon_events.append({
                "eventType": "CSPM_EXCEPTION_DUE_SOON",
                "findingId": finding_id,
                "reviewDate": review_date_str,
                "daysRemaining": days_remaining,
                "ticketRef": item.get("ticketRef", ""),
                "resourceId": item.get("resourceId", ""),
                "approvedBy": item.get("approvedBy", ""),
                "reasonType": item.get("reasonType", ""),
                "rationale": item.get("rationale", ""),
                "checkedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

    all_events = closed_events + due_soon_events
    if all_events:
        log_stream = time.strftime("%Y-%m-%d", time.gmtime())
        try:
            logs_client.create_log_stream(logGroupName=CSPM_EXCEPTION_LOG_GROUP, logStreamName=log_stream)
        except logs_client.exceptions.ResourceAlreadyExistsException:
            pass

        log_payload = [
            {"timestamp": int(time.time() * 1000), "message": json.dumps(ev)}
            for ev in all_events
        ]
        logs_client.put_log_events(
            logGroupName=CSPM_EXCEPTION_LOG_GROUP,
            logStreamName=log_stream,
            logEvents=log_payload,
        )

    return {
        "statusCode": 200,
        "checked": len(active_exceptions),
        "closed": len(closed_events),
        "dueSoon": len(due_soon_events),
    }