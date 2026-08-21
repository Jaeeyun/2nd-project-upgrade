# ADR-018: (초기안) SAML Role 5종 구조

- 상태: **Superseded by [ADR-019](ADR-019-eight-role-structure.md)** — 이 문서는 이력 보존용이며 현재 코드와 다르다
- 관련 파일: `12-iam-saml-roles.tf`(주석에서만 언급), `06-rds.tf`

## Context

[ADR-001](ADR-001-saml-temporary-credentials-for-humans.md)이 정의한 최초 3종 Role(`general-user`/`approver`/
`security-auditor`)로는 직무별 구분이 부족하다는 게 드러나, 직무 축을
`dev`/`ops`로 나누고 각각 `general`/`lead` 두 단계 신뢰도를 두는 5-Role
구조로 개정했다.

## Decision

1. Role을 `dev-general`/`dev-lead`/`ops-general`/`ops-lead`/
   `security-auditor` 5종으로 재구성한다.
2. IAM DB 인증 대상 Role 목록도 이 5종을 기준으로 갱신한다(`06-rds.tf`).

## Consequences

이 구조는 [ADR-019](ADR-019-eight-role-structure.md)에서 곧바로 개정됐다 — db 직무 축과
`dev-hr-backend` 전용 Role이 추가되어 8종이 됐고, ABAC(팀 태그 기반
접근 제어)도 이때 완전히 폐기됐다. 이 문서는 "한때 5종이었다"는 이력을
보존하기 위해서만 남겨두며, **현재 코드(`12-iam-saml-roles.tf`)는 이
문서가 아니라 [ADR-019](ADR-019-eight-role-structure.md)를 따른다.**
