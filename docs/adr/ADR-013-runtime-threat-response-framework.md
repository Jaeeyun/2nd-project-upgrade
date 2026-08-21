# ADR-013: 런타임 위협 탐지 대응은 사람 승인 기반 자동조치로

- 상태: Accepted — **재구성 신뢰도 낮음, 아래 참고**
- 관련 파일: `29-eks-pod-isolation.tf`

## ⚠️ 이 문서의 근거에 대해

이 ADR을 직접 설명하는 헤더 주석이나 README 항목은 코드 어디에도 없다.
유일한 근거는 `29-eks-pod-isolation.tf` 2번째 줄의 `ADR-013/014 확장`이라는
한 줄뿐이다. [ADR-014](ADR-014-asr-misconfiguration-remediation.md)(AWS ASR을 통한 설정 오류 자동조치)는 다른 파일에
헤더가 명확히 남아있어 재구성이 쉬웠지만, ADR-013은 "파드 격리가 이 ADR을
확장한 것"이라는 사실 외에 원래 무엇을 결정했는지가 코드에 남아있지 않다.
아래 내용은 파드 격리 구현이 실제로 따르고 있는 패턴을 근거로 역산 재구성한
것이며, 원래 ADR-013이 실제로 이 범위였는지는 확인할 수 없다.

## Context (추정)

설정 오류(misconfiguration)에 대한 자동조치([ADR-014](ADR-014-asr-misconfiguration-remediation.md))와는 별개로, 런타임에
발생하는 위협(비정상 프로세스 실행, 의심스러운 네트워크 연결 등 Falco/
GuardDuty EKS Protection이 탐지하는 종류)에 대한 대응 체계가 필요했을
것으로 보인다.

## Decision (추정)

1. 런타임 위협 탐지 시 Security Hub Custom Action을 통해 사람이 수동으로
   대응 Lambda를 트리거한다 — 자동 실행하지 않는다([ADR-005](ADR-005-human-approval-for-destructive-actions.md) 결정 5와
   동일한 패턴).
2. 최초 대응 조치로 "EKS 파드 격리"(quarantine 라벨 + deny-all
   NetworkPolicy)를 구현했다(`29-eks-pod-isolation.tf`).

## Consequences / 알려진 한계

- Falco가 아직 배포되지 않아([ADR-003](ADR-003-guardduty-foundational-only.md) 참고) 이 프레임워크의 실제 트리거
  경로는 GuardDuty EKS Protection 탐지나 수동 테스트 이벤트로 제한된다.
- Security Hub/GuardDuty의 실제 finding JSON에서 파드 이름·네임스페이스가
  어느 필드에 있는지는 finding 종류마다 달라서, `_extract_pod_info` 함수는
  "재확인 필요" 상태로 남아 있다 — 실제 GuardDuty EKS finding 샘플로
  검증이 더 필요하다.
