# ADR-009: EKS Pod Identity 활성화 + Pod Security 강제

- 상태: Accepted (결정 8은 [ADR-020](ADR-020-psa-replaces-kyverno.md)으로 개정됨)
- 관련 파일: `20-eks-pod-identity.tf`, `34-k8s-namespaces-rbac.tf`

## Context

EKS에 배포될 파드가 AWS API를 호출해야 할 때 어떤 방식으로 자격증명을 줄지,
그리고 파드가 지켜야 할 최소 보안 기준(privileged 컨테이너 금지 등)을
어떻게 강제할지 정해야 했다.

## Decision

1. **결정 1**: `eks-pod-identity-agent` 애드온을 클러스터에 활성화한다.
   지금은 배포된 애플리케이션이 없어 실제 ServiceAccount ↔ Role 연결
   예시는 만들지 않고, 애드온 활성화까지만 해뒀다.
2. **결정 3**: 이후 앱을 배포할 때는 ServiceAccount별로
   `aws_eks_pod_identity_association`을 추가하고, 각 앱 전용 최소권한
   Role([ADR-011](ADR-011-dedicated-least-privilege-roles.md))을 연결한다 — IAM Role 하나를 여러 앱이 공유하지
   않는다.
3. **결정 8(원안, 개정됨)**: Pod Security Standards(PSS) 강제는 원래
   Kyverno를 Helm으로 설치해서 담당하기로 했었다. 실제로 쓴 기능이
   baseline Audit 강제 하나뿐이었는데, 그것 때문에 컨트롤러 파드 + 웹훅 +
   Helm 배포 전체를 떠안았고, `terraform destroy` 시 Kyverno의 삭제 훅
   파드가 이미지를 못 받아와 destroy가 반복적으로 멈추는 문제를 실제로
   겪었다. 이후 K8s 1.25+ 내장 기능인 Pod Security Admission(PSA,
   네임스페이스 라벨만으로 동작, 별도 컨트롤러/웹훅 없음)으로
   대체했다 — 개정 내용은 [ADR-020](ADR-020-psa-replaces-kyverno.md) 참고.

## Consequences / 알려진 한계

- 결정 8은 최초 결정 그대로 구현된 적이 없다 — Kyverno는 실제로 배포된
  적 없이 PSA로 곧바로 대체됐다(정확히는 겪은 문제가 destroy 단계에서
  드러났으므로, "배포했다가 걷어낸" 것에 가깝다. 자세한 경위는
  `34-k8s-namespaces-rbac.tf` 주석과 [ADR-020](ADR-020-psa-replaces-kyverno.md) 참고).
- 지금 이 저장소에 배포된 애플리케이션이 없어서, Pod Identity 애드온이
  실제로 쓰이고 있는 ServiceAccount 연결 사례는 아직 없다(애드온만 켜진
  상태).
