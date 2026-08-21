# ADR-017: 미사용 Access Key도 발견은 자동, 삭제는 사람 승인

- 상태: Accepted
- 관련 파일: `21-config-managed-rules.tf`, `28-ciem-key-exception-flow.tf`, `scripts/ciem-key-exception-callback.py`, `scripts/ciem-key-exception-notify.py`

## Context

[ADR-007](ADR-007-ciem-unused-access-cycle.md)의 월간 CIEM 리포트는 IAM 권한 전반을 다루지만, 정적 Access
Key는 유출 시 파급력이 커서 더 촘촘한 개별 처리(소유자 특정 + 개별 승인)가
필요하다고 판단했다.

## Decision

1. **결정 1**: AWS Config 관리형 규칙으로 미사용/미회전 Access Key를
   탐지한다 — `IAM_USER_UNUSED_CREDENTIALS_CHECK`(90일 기준),
   `ACCESS_KEYS_ROTATED`(90일 기준)를 `21-config-managed-rules.tf`에
   명시적으로 선언한다.
2. **결정 2**: 탐지된 Access Key는 자동 삭제하지 않는다. 소유자를 찾아
   Slack으로 알리고(`scripts/ciem-key-exception-notify.py`), 소유자가
   "유지" 또는 "삭제" 버튼을 직접 눌러야 조치가 실행된다
   (`scripts/ciem-key-exception-callback.py`, `28-ciem-key-exception-flow.tf`).
   Slack App의 Signing Secret으로 요청 위조를 막는다.
3. 정적 Access Key가 필요한 예외 IAM User에는 `Owner` 태그(이메일)를
   붙여야 한다 — 없으면 "소유자 불명"으로만 알림이 간다.

## Consequences / 알려진 한계

- 소유자가 Slack 알림을 놓치거나 무시하면 미사용 Key가 계속 방치된다 —
  이 ADR은 "자동 삭제로 인한 서비스 장애"보다 "방치 위험"을 감수하는
  쪽을 택한 것이다.
- Slack App의 Bot Token/Signing Secret은 apply 후 수동으로 Secrets
  Manager에 채워야 동작한다 — Terraform에는 더미 값만 들어간다.
- API Gateway HTTP API가 폼 바디를 base64로 인코딩해서 넘기는데, 디코딩
  전 바디로 서명을 검증하면 항상 실패하는 버그를 겪었다 — 자세한 내용은
  [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md)의 CIEM Slack 인터랙티브 콜백 절 참고.
