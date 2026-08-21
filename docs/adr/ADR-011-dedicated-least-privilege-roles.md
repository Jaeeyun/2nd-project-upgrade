# ADR-011: 서비스/인스턴스마다 전용 최소권한 Role 발급

- 상태: Accepted
- 관련 파일: `11-keycloak.tf`, `24-ciem-lambda.tf`, `25-grafana.tf`, `20-eks-pod-identity.tf`

## Context

여러 EC2 인스턴스/Lambda가 각자 다른 AWS API를 호출해야 한다. 이들이
공용 Role 하나를 공유하면, 하나가 뚫렸을 때 다른 서비스의 권한까지 함께
노출되고(권한 폭발 반경 확대), 어떤 서비스가 실제로 어떤 권한을 쓰는지
추적하기도 어려워진다.

## Decision

1. 서비스/인스턴스마다 전용(dedicated) IAM Role + Instance Profile을
   따로 만든다 — 예: Keycloak EC2 전용 Role(`aws_iam_role.keycloak_ec2`,
   SSM 관리 전용, `11-keycloak.tf`), Grafana 전용 Role(`25-grafana.tf`).
2. **결정 5**: CIEM Lambda([ADR-007](ADR-007-ciem-unused-access-cycle.md))도 전용 최소권한 Role을 받는다
   (`24-ciem-lambda.tf`) — 다른 Lambda와 Role을 공유하지 않는다.
3. EC2 인스턴스는 [ADR-002](ADR-002-ssm-only-no-ssh.md)에 따라 IMDSv2를 강제한다
   (`metadata_options.http_tokens = "required"`) — 이 결정도 "전용 Role +
   최소한의 부가 방어"라는 이 ADR의 취지와 함께 적용된다.
4. Keycloak EC2 Role의 권한은 SSM 코어 관리 정책 + admin 비밀번호를
   저장/조회하기 위한 좁은 SSM Parameter Store 경로(`/keycloak/{name_prefix}/*`)로만
   한정한다 — 계정 전체 SSM 파라미터에 접근하지 않는다.

## Consequences / 알려진 한계

- Role 개수가 서비스 수만큼 늘어나 IAM 리소스가 많아진다 — 이는 의도된
  트레이드오프다(권한 폭발 반경을 줄이는 대가로 관리 대상이 늘어남).
- 새 서비스를 추가할 때마다 전용 Role을 새로 만드는 걸 잊으면 이 ADR이
  깨진다 — 코드 리뷰에서 "기존 Role 재사용" 패턴이 보이면 이 ADR 위반
  신호로 봐야 한다.
