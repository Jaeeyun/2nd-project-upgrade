# ADR 인덱스

이 디렉토리는 코드 곳곳(주로 각 `.tf` 파일 헤더 주석과 `README.md`)에 `ADR-001`
같은 형태로만 남아있던 설계 결정 참조를, 실제로 찾아볼 수 있는 문서로 정리한
것입니다.

> **재구성 문서임을 밝힙니다.** 이 프로젝트에는 원래 별도의 ADR 원문 파일이
> 없었습니다. 아래 20개 문서는 코드 주석 · README.md에 흩어져 있던 언급을
> 모아 사후에 재구성한 것이며, 결정 당시의 논의 기록(회의록, 후보안 비교 등)
> 원본은 존재하지 않습니다. "결정"과 "이유"는 코드에 남은 근거를 최대한
> 충실히 반영했지만, 표현 자체는 이 문서를 쓰면서 새로 정리한 것입니다.

## 목록

| ADR | 제목 | 상태 |
|---|---|---|
| [001](ADR-001-saml-temporary-credentials-for-humans.md) | 사람의 AWS 접근은 SAML 임시자격증명만 사용 | Accepted (Role 개수는 018→019로 개정) |
| [002](ADR-002-ssm-only-no-ssh.md) | EC2 접속은 SSM Session Manager만, SSH 전면 금지 | Accepted |
| [003](ADR-003-guardduty-foundational-only.md) | GuardDuty는 Foundational만, Runtime Monitoring은 Falco 담당 | Accepted (Falco 미배포 — 알려진 gap) |
| [004](ADR-004-aws-fsbp-account-baseline.md) | 계정 보안 베이스라인은 AWS FSBP 정렬 | Accepted (일부 결정은 수동 조치 필요) |
| [005](ADR-005-human-approval-for-destructive-actions.md) | 보안 알림 파이프라인 + 파괴적 자동조치는 사람 승인 필수 | Accepted |
| [006](ADR-006-github-actions-oidc.md) | GitHub Actions는 OIDC로 단기 Role, 정적 키 없음 | Accepted |
| [007](ADR-007-ciem-unused-access-cycle.md) | CIEM: 미사용 권한을 주기적으로 찾아 최소화 | Accepted (확장 진행 중) |
| [008](ADR-008-log-retention-worm-separation.md) | 로그는 실시간(짧게)과 장기 증적(WORM)을 분리 보관 | Accepted (Security Lake는 opt-in) |
| [009](ADR-009-eks-pod-identity-and-pss.md) | EKS Pod Identity 활성화 + Pod Security 강제 | Accepted (결정 8은 020으로 개정) |
| [010](ADR-010-observability-grafana-login.md) | Grafana 로그인 연동 방식 | Accepted (원안 OIDC → SAML로 개정) |
| [011](ADR-011-dedicated-least-privilege-roles.md) | 서비스/인스턴스마다 전용 최소권한 Role 발급 | Accepted |
| [012](ADR-012-security-group-hygiene.md) | 보안그룹 위생: SSH 금지, SG-to-SG 참조 우선 | Accepted |
| [013](ADR-013-runtime-threat-response-framework.md) | 런타임 위협 탐지 대응은 사람 승인 기반 자동조치로 | Accepted (근거가 가장 희박한 문서 — 아래 참고) |
| [014](ADR-014-asr-misconfiguration-remediation.md) | 설정 오류 자동조치는 AWS ASR을 CloudFormation으로 배포 | Accepted (오케스트레이터만 배포됨 — 알려진 gap) |
| [015](ADR-015-security-lake-native-sources.md) | Security Lake에 네이티브 지원 로그 소스를 전부 등록 | Accepted (opt-in) |
| [016](ADR-016-python-automation-script-standard.md) | Lambda 자동화 스크립트는 공통 구조를 따름 | Accepted (근거가 가장 희박한 문서 — 아래 참고) |
| [017](ADR-017-unused-access-human-approval-flow.md) | 미사용 Access Key도 발견은 자동, 삭제는 사람 승인 | Accepted |
| [018](ADR-018-five-role-structure-superseded.md) | (초기안) SAML Role 5종 구조 | **Superseded by [019](ADR-019-eight-role-structure.md)** |
| [019](ADR-019-eight-role-structure.md) | SAML Role 8종 + ABAC 폐기 | Accepted (가장 최근 개정) |
| [020](ADR-020-psa-replaces-kyverno.md) | Kyverno 대신 K8s 내장 PSA로 Pod Security 강제 | Accepted (009 결정 8 개정) |

## 근거가 특히 희박한 문서

**ADR-013**, **ADR-016**은 코드에 `ADR-013/014 확장`, `ADR-016(Python 자동화
스크립트 표준)`처럼 한 번씩만 스치듯 언급되고, 그 결정 자체를 설명하는
헤더 주석은 어디에도 없습니다. 해당 두 문서는 그 짧은 언급 + 실제로 코드가
따르고 있는 패턴을 근거로 이 문서를 쓰면서 추정 재구성한 것이라, 신뢰도가
다른 18개보다 낮습니다. 각 문서 상단에 이 사실을 다시 한번 표시해뒀습니다.

## 번호가 실제로 의미하는 것

`ADR-001 결정 5`처럼 "결정 N"이 붙어 나오는 경우가 많은데, 이는 하나의 ADR
안에 여러 개의 하위 결정 항목이 번호로 나열되어 있었다는 뜻입니다(예: ADR-004는
결정 1~8). 각 문서의 "결정" 섹션에 그 하위 번호를 그대로 보존했습니다 — 코드
주석이 그 번호를 인용하고 있어서, 번호를 바꾸면 코드-문서 간 참조가 끊어집니다.
