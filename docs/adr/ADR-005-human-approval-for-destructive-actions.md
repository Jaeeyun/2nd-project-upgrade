# ADR-005: 보안 알림 파이프라인 + 파괴적 자동조치는 사람 승인 필수

- 상태: Accepted
- 관련 파일: `23-security-alerting.tf`, `18-guardduty.tf`, `25-grafana.tf`, `29-eks-pod-isolation.tf`, `35-session-revocation.tf`, `36-ciem-boundary-drift-check.tf`, `scripts/ciem-key-exception-callback.py`, `scripts/ciem-key-exception-notify.py`, `scripts/eks-pod-isolate.py`, `scripts/session-revoke.py`, `scripts/ciem-boundary-drift-notify.py`

## Context

보안 파인딩이 발생했을 때 "누구에게 어떻게 알릴 것인가"와, 그 파인딩에
대한 조치를 "자동으로 실행할 것인가 사람이 승인한 뒤 실행할 것인가"를
정해야 했다. 이 프로젝트에서 만드는 자동조치 중 상당수(세션 강제 종료,
파드 격리, IAM 정책 축소, Access Key 삭제)는 되돌리기 어렵거나 정상
사용자에게도 영향을 줄 수 있는 조치라, 전면 자동화 대신 "발견은 자동,
실행은 사람"이라는 공통 패턴을 채택했다.

## Decision

1. **결정 3**: 온프레미스에 이미 있는 Grafana를 재사용해 신규 AWS 비용을
   내지 않는다 — 실제로는 온프레미스 Grafana가 준비되지 않아 Amazon
   Managed Grafana로 대체됐다([ADR-010](ADR-010-observability-grafana-login.md) 참고).
2. **결정 4**: GuardDuty/Security Hub의 High/Critical(`severity >= 7`)
   파인딩만 EventBridge로 필터링해 SNS로 보내고, SNS 구독자로 AWS
   Chatbot(Slack)과 PagerDuty를 붙인다. Low/Medium은 알림 피로도를 막기
   위해 걸러낸다.
3. **결정 5**: 사람 승인 없이 자동으로 실행하지 않는 조치 목록 — EKS 파드
   격리(`29-eks-pod-isolation.tf`), 세션 강제 종료(`35-session-revocation.tf`),
   IAM 정책 축소(`36-ciem-boundary-drift-check.tf`), Access Key
   삭제(`28-ciem-key-exception-flow.tf`, [ADR-017](ADR-017-unused-access-human-approval-flow.md)). 트리거 방식은 둘 중
   하나다: Security Hub Custom Action(사람이 콘솔에서 버튼 클릭) 또는
   Slack 인터랙티브 버튼.

## Consequences / 알려진 한계

- 사람이 승인 버튼을 누를 때까지 위협이 방치된다는 트레이드오프가 있다 —
  이 프로젝트는 "빠른 자동 대응"보다 "오탐으로 인한 서비스 장애 방지"를
  우선한 것이다.
- 알림 채널(Slack/PagerDuty)이 죽으면 사람이 알림 자체를 못 받는다는
  단일 장애점이 있다.
- Grafana 관련 결정 3은 실제로 온프레미스 자원이 없어서 그대로
  실현되지 못했고 [ADR-010](ADR-010-observability-grafana-login.md)에서 사실상 수정됐다 — ADR을 고치는 대신
  새 ADR로 결정을 개정하는 이 저장소의 관례를 여기서도 확인할 수 있다.
