# ADR-019: SAML Role 8종 + ABAC 폐기

- 상태: Accepted (가장 최근 개정, [ADR-018](ADR-018-five-role-structure-superseded.md)을 대체)
- 관련 파일: `12-iam-saml-roles.tf`, `34-k8s-namespaces-rbac.tf`, `11-keycloak.tf`, `04-eks.tf`, `25-grafana.tf`, `README.md`

## Context

[ADR-018](ADR-018-five-role-structure-superseded.md)의 5-Role 구조(`dev`/`ops` × `general`/`lead` + 감사)에는
db 직무 축이 빠져 있었고, HR 백엔드처럼 별도로 격리해야 하는 앱의 접근
범위를 Role 하나로 표현할 수 없었다. 또한 애초에 검토했던 ABAC(팀 태그
기반 접근 제어)가 EKS 워커 노드처럼 여러 팀 파드가 한 노드를 공유하는
환경에서는 "리소스 하나는 한 팀만 쓴다"는 전제 자체가 성립하지 않는다는
게 확인됐다.

## Decision

1. **결정 1**: ABAC(팀 태그) 조건을 전부 폐기한다. 관련 SAML 매퍼(`team`
   속성)도 전부 제거한다.
2. IAM Role을 8종으로 확장한다: `dev-general`/`dev-lead`/
   `dev-hr-backend`/`db-general`/`db-lead`/`ops-general`/`ops-lead`/
   `security-auditor`. `dev-*`/`db-*`는 EKS 노드 SSM 접근 자체가 없다
   (운영 Role만 가능) — 개발자가 파드를 봐야 하면 `kubectl`을 쓴다.
3. **앱(파드)별 접근 범위는 AWS Role이 아니라 K8s 네임스페이스 + RBAC이
   담당한다**(`34-k8s-namespaces-rbac.tf`). `frontend`/`employee-backend`는
   `dev-general`(조회)/`dev-lead`(수정) 그룹에 열려 있고, `hr-backend`만
   전용 Role(`dev-hr-backend`)로 분리했다.
4. **결정 4(검토했던 대안)**: `hr-backend`처럼 더 좁게 격리해야 하는
   접근은 최초에 개인 사용자명 허용목록으로 만들려 했으나,
   `RoleSessionName`이 `AssumeRoleWithSAML`을 직접 호출하는 경로에서
   이론상 위조 가능하다는 게 발견되어, 위조 불가능한 Role ARN 기반
   경계(전용 Role의 K8s Group)로 대체했다.
5. Amazon Managed Grafana([ADR-010](ADR-010-observability-grafana-login.md))의 관리자 권한은 8-Role 중 리드
   2종(`dev-lead`, `ops-lead`)에만 부여한다(`25-grafana.tf`).

## Consequences / 알려진 한계

- `04-eks.tf`에 EKS Access Entry 인증 모드(`access_config`)가 빠져있던
  버그가 이 작업 중 발견되어 함께 고쳐졌다 — 이게 없으면 Access Entry
  리소스들이 전부 apply 시 실패했을 것이다.
- **결정 4의 대안조차 완전한 해법은 아니다.** `hr-backend` Access
  Entry의 `user_name`도 여전히 `RoleSessionName`을 그대로 K8s
  사용자명으로 노출한다(`34-k8s-namespaces-rbac.tf`) — hr-backend 개인
  식별이 이 값에 의존하는 한, "이 Role을 assume할 자격 자체(Keycloak
  그룹 멤버십)는 위조 불가능하다"는 선에서 안전성을 확보한 것이지,
  `RoleSessionName` 위조 가능성 자체가 완전히 해소된 것은 아니다 —
  후속 검증이 필요하다고 코드에 명시되어 있다.
- ABAC 폐기로 `Team` 태그 기반 검증은 더 이상 EKS 노드로는 할 수 없다 —
  ABAC 로직(정책의 `ssm:resourceTag/Team` 조건문) 자체는 여전히
  `policies/03-role-general-user.json.tpl`에 남아 있어 코드 리뷰로만
  확인 가능하고, 필요하면 `Team` 태그를 붙인 임시 EC2로 그때그때
  검증해야 한다.
