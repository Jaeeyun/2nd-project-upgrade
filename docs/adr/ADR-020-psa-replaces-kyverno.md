# ADR-020: Kyverno 대신 K8s 내장 PSA로 Pod Security 강제

- 상태: Accepted ([ADR-009](ADR-009-eks-pod-identity-and-pss.md) 결정 8을 개정)
- 관련 파일: `34-k8s-namespaces-rbac.tf`, ~~`26-kyverno.tf`~~(제거됨), `README.md`

## Context

[ADR-009](ADR-009-eks-pod-identity-and-pss.md) 결정 8은 Pod Security Standards(PSS) 강제를 Kyverno로
하기로 정했었다. 실제로 사용한 Kyverno 기능은 baseline Audit 강제
하나뿐이었는데, 그 기능 하나 때문에 Kyverno 컨트롤러 파드 + 웹훅 + Helm
배포 전체를 떠안아야 했다. `terraform destroy` 실행 시 Kyverno의 삭제 훅
파드가 이미지를 못 받아와 destroy가 반복적으로 멈추는 문제를 실제로
겪은 뒤, 더 가벼운 대안으로 교체하기로 했다.

## Decision

1. `26-kyverno.tf`(Kyverno Helm 설치)를 제거한다.
2. 대신 Kubernetes 1.25+ 내장 기능인 Pod Security Admission(PSA)을
   쓴다 — 네임스페이스 라벨(`pod-security.kubernetes.io/audit` 등)만으로
   동작하고, 별도 컨트롤러/웹훅이 필요 없다(`34-k8s-namespaces-rbac.tf`).
3. 현재는 `audit`/`warn` 수준만 `baseline`으로 설정해 위반을 감시만
   하고 막지는 않는다(POL-01) — 충분한 관찰 후 `enforce`도
   `baseline`으로 올리는 게 다음 단계(POL-02, Enforce 전환)다.

## Consequences / 알려진 한계

- PSA는 Kyverno만큼 세밀한 커스텀 정책(임의 조건의 admission 규칙)은
  못 만든다 — 이 프로젝트가 실제로 쓴 기능이 baseline Audit 하나뿐이라
  이 트레이드오프를 받아들였다. 더 세밀한 정책이 필요해지면 다시
  Kyverno 같은 도구가 필요할 수 있다.
- 아직 `enforce` 단계로 전환하지 않아서, 지금은 위반이 감지되어도 파드
  생성 자체를 막지는 못한다(경고만 남는다).
