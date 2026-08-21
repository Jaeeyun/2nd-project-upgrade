# ADR-012: 보안그룹 위생 — SSH 금지, SG-to-SG 참조 우선

- 상태: Accepted
- 관련 파일: `11-keycloak.tf`, `33-pomerium.tf`, `21-config-managed-rules.tf`, `scripts/security-hub-suppress-accepted-risks.sh`

## Context

보안그룹 규칙을 CIDR 기반으로만 쓰면, 참조하는 쪽의 IP가 바뀔 때마다 규칙을
같이 고쳐야 하고, "이 트래픽이 정확히 어디서 오는지"가 CIDR 숫자만 봐서는
드러나지 않는다. 같은 VPC/Peering 안에서 통신하는 리소스끼리는 CIDR 대신
보안그룹을 직접 참조하는 방식을 우선하기로 했다.

## Decision

1. 모든 보안그룹은 SSH(22번 포트) 인바운드를 열지 않는다([ADR-002](ADR-002-ssm-only-no-ssh.md)와
   결합) — 기능 단위로 최소한만 연다(예: Keycloak SG는 admin CIDR에서의
   443만 허용).
2. **결정 2**: 같은 VPC/Peering 관계에 있는 리소스 간 통신은 CIDR이 아니라
   SG-to-SG 참조(`referenced_security_group_id`)로 표현한다 — 예:
   Keycloak SG에 "Pomerium SG에서 오는 443만 추가로 허용"
   (`33-pomerium.tf`의 `aws_vpc_security_group_ingress_rule.keycloak_https_from_pomerium`).
3. **결정 7**: FSBP([ADR-004](ADR-004-aws-fsbp-account-baseline.md))가 대부분의 SG/IAM 위생을 이미 커버하지만,
   "명시적으로 켜져 있는지"를 이 저장소 코드에서 직접 확인할 수 있도록
   AWS Config 관리형 규칙(`restricted_ssh` 등)을 별도로 선언한다 — FSBP와
   중복 평가되어도 문제 없다(같은 리소스를 두 표준이 각자 평가하는 것뿐).

## Consequences / 알려진 한계

- SG-to-SG 참조는 같은 VPC 또는 Peering된 VPC 안에서만 동작한다 — VPC
  경계를 넘어가는 트래픽(예: 완전히 분리된 계정)에는 이 방식을 못 쓴다.
- Security Hub가 "SSH 0.0.0.0/0 허용" 같은 특정 패턴만 탐지하는
  통제(EC2.13 계열)는 이 ADR 덕분에 대부분 통과하지만, 그 외의 광범위한
  인바운드 규칙(예: 애플리케이션 포트를 0.0.0.0/0으로 여는 것)까지 막아주지는
  않는다 — 그런 항목은 `scripts/security-hub-suppress-accepted-risks.sh`에서
  개별적으로 검토·수용 처리된다.
