"""
매월 1회 IAM Access Analyzer의 Unused Access 분석 결과를 모아 Slack(SNS 경유)으로
요약 보고하는 스크립트. ADR-007 결정 4, ADR-016(Python 자동화 스크립트 표준) 적용.

실행 위치: Lambda (EventBridge Scheduler가 매월 1일 트리거)
권한: 24-ciem-lambda.tf의 전용 최소권한 Role (ADR-011 결정 5)
"""
import boto3
import json
import os

analyzer_client = boto3.client("accessanalyzer")
sns_client = boto3.client("sns")

ANALYZER_ARN = os.environ["ANALYZER_ARN"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def handler(event, context):
    findings = []
    paginator = analyzer_client.get_paginator("list_findings_v2")

    try:
        for page in paginator.paginate(
            analyzerArn=ANALYZER_ARN,
            filter={"status": {"eq": ["ACTIVE"]}},
        ):
            findings.extend(page.get("findings", []))
    except Exception as e:
        _notify(f"❌ Unused Access 분석 실패: {e}")
        raise

    if not findings:
        _notify("✅ 이번 달 Unused Access 파인딩 없음")
        return {"statusCode": 200, "findings": 0}

    summary_lines = [f"📋 이번 달 Unused Access 파인딩: {len(findings)}건"]
    for f in findings[:20]:  # Slack 메시지가 너무 길어지지 않게 상위 20건만
        resource = f.get("resource", "unknown")
        finding_type = f.get("findingType", "unknown")
        summary_lines.append(f"  - [{finding_type}] {resource}")

    if len(findings) > 20:
        summary_lines.append(f"  ... 외 {len(findings) - 20}건 (콘솔에서 전체 확인)")

    _notify("\n".join(summary_lines))
    return {"statusCode": 200, "findings": len(findings)}


def _notify(message: str):
    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="CIEM: Unused Access 월간 분석 결과",
        Message=message,
    )
