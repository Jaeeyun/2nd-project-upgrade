# ADR-007: CIEM — 미사용 권한을 주기적으로 찾아 최소화

- 상태: Accepted (확장 진행 중, 아래 참고)
- 관련 파일: `24-ciem-lambda.tf`, `22-cicd-oidc.tf`, `36-ciem-boundary-drift-check.tf`, `scripts/ciem-unused-access-report.py`

## Context

IAM Role/사용자가 처음 만들어질 때 넓게 잡은 권한이 시간이 지나도 좁혀지지
않고 그대로 남는 문제(권한 과다 누적)를 막아야 했다. 한 번에 완벽한
최소권한을 예측해서 부여하는 대신, "일단 관찰 가능한 넓이로 시작 → 실사용
데이터를 근거로 주기적으로 좁힌다"는 CIEM(Cloud Infrastructure Entitlement
Management) 사이클을 도입했다.

## Decision

1. **결정 1**: 새로 만드는 Role(예: [ADR-006](ADR-006-github-actions-oidc.md)의 CI Role)은 넓은 베이스라인
   권한으로 시작하고, 4주 관찰 기간 후 실사용 데이터를 근거로 최소화한다.
2. **결정 4**: IAM Access Analyzer의 Unused Access 분석(90일 이상 미사용
   권한 탐지)을 매월 1회 Lambda로 실행해 Slack에 요약 보고한다
   (`24-ciem-lambda.tf` + `scripts/ciem-unused-access-report.py`).
3. 월간 주기로는 빠른 대응이 안 되는 케이스(권한 드리프트를 더 짧은
   주기로 감지하고 싶을 때)를 위해 `36-ciem-boundary-drift-check.tf`가
   이 ADR을 확장한다 — IAM Access Analyzer Policy Generation으로 실제
   API 사용 이력을 분석하고, 안 쓴 권한이 있으면 Slack으로 알린다.
4. 삭제/축소는 자동 실행하지 않는다 — "발견은 자동, 실행은 사람 승인
   후"라는 공통 패턴([ADR-005](ADR-005-human-approval-for-destructive-actions.md) 결정 5, [ADR-017](ADR-017-unused-access-human-approval-flow.md))을 그대로 따른다.

## Consequences / 알려진 한계

- 월간 사이클(결정 4)은 90일 기준이라 신뢰할 만하지만, 확장판(짧은 주기
  드리프트 체크)의 기본 관찰 기간(3시간)은 데모/테스트용으로 지나치게
  짧다 — 분기별/저빈도 정당 업무 권한이 "미사용"으로 계속 오탐되어 Slack
  알림 피로도만 높아질 수 있다. 실제 운영 전환 시에는 90일 기준처럼 훨씬
  길게 늘려야 한다.
- CIEM 결과를 Slack으로만 통보하고 자동 적용하지 않으므로, 사람이 실제로
  버튼을 눌러 승인하지 않으면 권한은 계속 넓은 채로 남는다.
