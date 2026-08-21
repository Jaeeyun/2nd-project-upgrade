# ADR-004: 계정 보안 베이스라인은 AWS FSBP 정렬

- 상태: Accepted (결정 3/7은 이 저장소 범위 밖 — 아래 참고)
- 관련 파일: `10-security-baseline.tf`, `01-variables.tf`, `08-cloudtrail.tf`, `18-guardduty.tf`

## Context

계정 전체에 적용할 보안 표준을 하나 골라야 했다. Security Hub가 지원하는
두 대표 표준 중 AWS Foundational Security Best Practices(FSBP)를 기본
베이스라인으로 삼고, CIS AWS Foundations Benchmark는 감사 대응 등으로
번호 체계 증적이 별도로 필요할 때만 선택적으로 켜기로 했다(둘 다 상시
켜두면 같은 리소스를 두 표준이 각자 평가해 콘솔 노이즈가 늘어난다).

## Decision

이 프로젝트(Terraform)로 구현 가능한 항목만 아래처럼 반영한다:

1. Security Hub CSPM + FSBP 표준 활성화. CIS는
   `var.enable_cis_benchmark`(기본값 `false`)로 선택적 활성화.
2. AWS Config 활성화 — 리소스 설정 변경 이력 추적, Security Hub CSPM
   판정의 근거로 사용.
3. **(이 저장소 범위 밖)** 루트/IAM 사용자 MFA 필수화 — 루트 계정 MFA
   등록은 콘솔에서 사람이 직접 해야 하는 작업이라 Terraform으로 강제할 수
   없다. IAM 사용자 MFA 강제 정책(`require_mfa`)은 준비만 해뒀다 — 이
   저장소는 사람의 AWS 접근을 [ADR-001](ADR-001-saml-temporary-credentials-for-humans.md)(SAML/임시자격증명)로 처리해서
   현재 attach할 IAM 사용자가 없다.
4. 계정 단위 S3 Block Public Access.
5. **(다른 파일에 구현됨)** CloudTrail 전 리전 + 로그 무결성 검증 —
   `08-cloudtrail.tf`에 이미 구현.
6. Budgets 월 예산 알림(80% 도달 시) + Cost Anomaly Detection.
7. **(이 저장소 범위 밖)** 장기 Access Key 발급 금지 — 결정 3과 같은
   이유로 발급 대상 IAM 사용자가 없어 별도 리소스가 불필요.
8. **(다른 ADR 소관)** GuardDuty — [ADR-003](ADR-003-guardduty-foundational-only.md) 참고.

## Consequences / 알려진 한계

- 결정 3, 7은 "리소스가 없는 것" 자체가 구현이다 — 코드만 보면 누락처럼
  보일 수 있어 이 문서와 `10-security-baseline.tf` 헤더 주석에 이유를
  명시해뒀다.
- Security Hub 점수(Passed/Failed)가 Config 재평가 지연으로 apply 직후
  일시적으로 튀는 경우가 있었다 — 이는 이 ADR의 결함이 아니라 AWS 쪽
  백그라운드 재평가 지연 때문이며, 자세한 진단 과정은
  [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md)의 "Security Hub/Config" 절 참고.
