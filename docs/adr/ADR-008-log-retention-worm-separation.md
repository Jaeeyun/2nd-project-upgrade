# ADR-008: 로그는 실시간(짧게)과 장기 증적(WORM)을 분리 보관

- 상태: Accepted (본체인 Security Lake는 `var.enable_security_lake`로 opt-in)
- 관련 파일: `19-security-lake.tf`, `17-rds-audit-worm.tf`, `06-rds.tf`, `01-variables.tf`

## Context

보안/감사 로그를 어디에 얼마나 보관할지 정해야 했다. CloudWatch에 전부
장기 보관하면 조회는 빠르지만 비용이 크고, 위변조 방지(감사 요구사항)가
안 된다. 반대로 처음부터 저비용 아카이브에만 넣으면 운영 중 빠른 조회가
안 된다. 그래서 "최근 것은 빠르게 조회 가능한 곳에 짧게, 오래된 것은
저렴하고 위변조 불가능한 곳에 길게"로 역할을 나눴다.

## Decision

1. **본체**: CloudTrail, VPC Flow Logs, GuardDuty, Route 53 Resolver
   로그를 Amazon Security Lake(OCSF 포맷)로 통합한다(`19-security-lake.tf`,
   [ADR-015](ADR-015-security-lake-native-sources.md)와 결합). Security Lake는 계정당 리전당 1개만 활성화
   가능해서 `enable_security_lake` 변수로 켜고 끌 수 있게 했다.
2. **결정 2**: 장기 보관 버킷은 S3 Object Lock **Compliance 모드**를
   쓴다 — 루트 계정을 포함해 누구도 보존 기간 내에는 삭제/수정할 수 없다.
3. **결정 3**: 30일 경과 후 Glacier Deep Archive로 자동 전환한다 —
   장기 보관 비용을 최대 95% 수준까지 절감하는 근거로 채택.
4. **RDS 로그 예외**: RDS PostgreSQL 로그는 Security Lake의 네이티브
   지원 소스가 아니다(OCSF 커스텀 소스를 직접 만들어야 하는 별도의 큰
   작업). 그래서 Security Lake 통합까지는 하지 않고, `17-rds-audit-worm.tf`가
   결정 2/3의 핵심 원칙만 별도 경로로 재사용한다: RDS →
   CloudWatch Logs(30일, `06-rds.tf`) → 구독 필터 → Kinesis Data
   Firehose → S3(Object Lock, `rds_audit_worm_retention_days`,
   기본 365일).

## Consequences / 알려진 한계

- Security Lake는 opt-in이라, `enable_security_lake=false`인 환경에서는
  이 ADR의 본체(결정 1)가 아예 적용되지 않은 상태다.
- RDS 로그는 Security Lake/OCSF로 정식 통합되지 않았다 — 별도 경로(WORM
  버킷)로 원칙만 재사용했을 뿐, 다른 로그 소스와 같은 파이프라인에서
  조회/상관분석은 안 된다.
- Compliance 모드는 보존 기간이 지나기 전까지 계정 소유자도 삭제할 수
  없다 — 기간을 잘못 설정하면(예: 너무 길게) 되돌릴 방법이 없다는 점에
  주의해야 한다.
