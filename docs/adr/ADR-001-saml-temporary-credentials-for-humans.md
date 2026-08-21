# ADR-001: 사람의 AWS 접근은 SAML 임시자격증명만 사용

- 상태: Accepted (Role 개수는 [ADR-018](ADR-018-five-role-structure-superseded.md) → [ADR-019](ADR-019-eight-role-structure.md)로 두 차례 개정)
- 관련 파일: `12-iam-saml-roles.tf`, `10-security-baseline.tf`, `11-keycloak.tf`, `06-rds.tf`, `21-config-managed-rules.tf`, `27-asr-remediation.tf`, `37-iam-bootstrap-users-group-migration.tf`

## Context

사람이 AWS 계정에 접근하는 방식을 정해야 했다. 후보는 크게 세 가지였다: (1)
IAM 사용자 + 장기 Access Key, (2) AWS Organizations + IAM Identity Center,
(3) 온프레미스 IdP(Keycloak) + SAML 2.0 연동 임시자격증명(STS).

(1)은 장기 키 유출 위험과 AWS FSBP 위반(장기 Access Key 금지, [ADR-004](ADR-004-aws-fsbp-account-baseline.md))이
바로 걸린다. (2)는 이 프로젝트가 시뮬레이션하는 "온프레미스-하이브리드"
전제(사내에 이미 Keycloak 같은 IdP가 있다는 가정)와 맞지 않고, AWS
Organizations 자체가 프리티어 예산 안에서 검증하기엔 과한 것으로 판단해
기각했다(`21-config-managed-rules.tf`, `27-asr-remediation.tf` 주석 참고 —
이 기각 결정이 이후 "IMDSv2를 계정 전체에 SCP로 강제할 수 없다", "ASR을
member-roles 없이 admin 템플릿 단독으로 배포한다" 등 여러 후속 결정의
전제로 계속 인용된다).

## Decision

1. 사람의 AWS 접근은 전부 Keycloak SAML 2.0 IdP → `aws_iam_saml_provider` →
   `AssumeRoleWithSAML`을 통한 임시자격증명(STS)으로만 이루어진다. IAM
   사용자를 새로 만들어 사람에게 주는 방식은 쓰지 않는다.
2. Role은 직무 단위로 나눈다(최초 3종: `general-user`/`approver`/
   `security-auditor` — 이후 5종을 거쳐 8종으로 확장, [ADR-019](ADR-019-eight-role-structure.md) 참고).
3. `security-auditor` Role은 신뢰 정책에 CIDR 조건을 걸어, 승인된 네트워크
   대역에서만 assume 가능하게 제한한다.
4. AWS Organizations 도입은 프리티어 비용 문제로 기각한다 — 이 결정으로
   계정 전체에 SCP를 강제할 방법이 없다는 제약이 여러 곳(IMDSv2 강제,
   ASR member 템플릿 등)에 전파된다.
5. RDS 접속도 정적 비밀번호가 아니라 같은 IAM Role 신원으로 받는 IAM DB
   인증 토큰을 쓴다(`06-rds.tf`의 `iam_database_authentication_enabled`).
6. 예외적으로 부트스트랩/비상 접근용 IAM 사용자 2개(`terraform-admin`,
   `dev-admin`)는 유지하되, 권한은 IAM Group을 통해서만 부여한다(직접
   attach 금지 — Security Hub IAM.2 대응, `37-iam-bootstrap-users-group-migration.tf`).
7. **결정 7**: 모든 SAML 기반 Role에 Permission Boundary를 상한선으로
   적용한다 — Role 정책이 아무리 넓어도 Boundary 밖으로는 나갈 수 없다.

## Consequences / 알려진 한계

- Keycloak 자체가 단일 장애점이자 공격 표면이다 — Keycloak이 죽으면 사람은
  아무도 AWS에 못 들어간다(그래서 예외적으로 부트스트랩용 IAM 사용자 2개를
  남겨뒀다, 결정 6).
- `RoleSessionName`(Keycloak username을 그대로 세션 이름으로 사용)은
  `AssumeRoleWithSAML`을 직접 호출하는 경로에서 이론적으로 위조 가능하다는
  한계가 나중에 발견됐다([ADR-019](ADR-019-eight-role-structure.md) 참고, 개인 허용목록 방식을 Role 기반으로 교체한 계기).
- Organizations 없이 SCP 강제가 불가능하다는 제약은 여러 Config 규칙이
  "탐지만 하고 강제는 못 함"으로 타협하게 만들었다(`21-config-managed-rules.tf`의
  IMDSv2 체크가 대표적).
