# ADR-015: Security Lake에 네이티브 지원 로그 소스를 전부 등록

- 상태: Accepted (`var.enable_security_lake`로 opt-in)
- 관련 파일: `19-security-lake.tf`

## Context

[ADR-008](ADR-008-log-retention-worm-separation.md)이 결정한 "장기 증적은 통합 저장소로"라는 원칙의 실행 수단으로
Amazon Security Lake를 채택했는데, Security Lake가 기본 제공(네이티브)으로
지원하는 로그 소스는 커스텀 OCSF 변환 작업 없이 바로 등록할 수 있어, 그런
소스는 전부 등록하기로 했다.

## Decision

1. Security Lake가 네이티브로 지원하는 소스를 전부 등록한다: CloudTrail,
   VPC Flow Logs, Security Hub findings, EKS Audit Logs.
2. Security Lake 데이터 보존 기간은 `security_lake_retention_days`
   변수로 설정하며 기본값 365일이다. 이 값은 반드시 30일보다 커야 한다는
   유효성 검증이 걸려 있다 — [ADR-008](ADR-008-log-retention-worm-separation.md) 결정 3(30일 후 Glacier 전환)보다
   짧게 설정하면 전환 로직과 모순되기 때문이다.
3. Security Lake는 계정당 리전당 1개만 활성화 가능하므로,
   `enable_security_lake` 변수로 켜고 끌 수 있게 해서 이미 다른 방식으로
   Security Lake가 켜져 있는 계정과의 충돌을 피할 수 있게 했다.
4. `meta_store_manager_role_arn`에 붙는 관리형 정책 ARN은 AWS가 바꿀 수
   있는 값이라 apply 전 재확인이 필요하다.

## Consequences / 알려진 한계

- RDS 로그는 네이티브 지원 소스가 아니라서 이 ADR의 범위에 들어오지
  않는다 — 별도 경로로 처리된다([ADR-008](ADR-008-log-retention-worm-separation.md)의 RDS 예외 참고).
- opt-in 변수이므로, 기본값(`false`)으로 apply하면 이 ADR 자체가 아예
  적용되지 않은 상태로 남는다 — 다른 문서에서 "Security Lake로 통합됨"이라고
  설명하는 부분은 이 변수가 켜져 있다는 전제다.
