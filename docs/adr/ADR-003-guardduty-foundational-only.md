# ADR-003: GuardDuty는 Foundational만, Runtime Monitoring은 Falco 담당

- 상태: Accepted (Falco가 아직 배포되지 않아 실질적으로 런타임 탐지 공백이 있음 — 알려진 gap)
- 관련 파일: `18-guardduty.tf`, `23-security-alerting.tf`

## Context

컨테이너/런타임 위협 탐지를 GuardDuty의 Runtime Monitoring 기능으로 할지,
별도 오픈소스 도구(Falco)로 할지 정해야 했다. 둘 다 켜면 같은 영역을
이중으로 탐지하게 되어 리소스 낭비와 비용 중복이 생긴다.

## Decision

1. GuardDuty는 Foundational 탐지 기능만 켠다: CloudTrail 기반 이상탐지,
   알려진 악성 IP 대조, S3 Protection, EKS Audit Log 감시, EBS Malware
   Protection.
2. **결정 2/3**: EKS/EC2 컨테이너 런타임 에이전트 기반 탐지
   (`EKS_RUNTIME_MONITORING`, `RUNTIME_MONITORING` 기능)는 의도적으로
   켜지 않는다 — 그 영역은 Falco가 담당하기로 결정했기 때문이다. 코드
   상으로는 이 기능을 켜는 리소스가 "존재하지 않는 것" 자체가 결정의
   표현이다.
3. **결정 4**: GuardDuty/Security Hub 파인딩을 EventBridge로 SNS에 보낼 때,
   원본 ASFF/GuardDuty JSON은 장황하므로 Input Transformer로 필요한
   필드(severity, title 등)만 축약해서 보낸다 — 이 방침은
   [ADR-005](ADR-005-human-approval-for-destructive-actions.md) 결정 4에서도 그대로 재사용된다.
4. Falco는 "EKS/EC2(K3s) 양쪽"에 배포되어야 이 ADR의 전제가 완성되는데,
   K3s 노드 자체가 아직 이 저장소에 없다 — Falco 도입은 다음 단계로
   남겨졌다.

## Consequences / 알려진 한계

- **Falco가 실제로 배포되지 않은 상태에서 GuardDuty Runtime Monitoring도
  꺼져 있으므로, 지금 이 시점의 인프라는 컨테이너 런타임 위협에 대한
  실질적인 탐지 공백이 있다.** ADR 자체는 유효하지만 구현이 아직
  절반(GuardDuty 쪽 "끄기"만 완료, Falco 쪽 "켜기"는 미완료)이다.
- [29-eks-pod-isolation.tf](../../29-eks-pod-isolation.tf)의 파드 격리
  자동조치는 Falco/GuardDuty 탐지를 전제로 만들어졌지만, Falco가 없는
  지금은 GuardDuty EKS Protection 탐지나 수동 테스트 이벤트로만 트리거
  가능하다.
