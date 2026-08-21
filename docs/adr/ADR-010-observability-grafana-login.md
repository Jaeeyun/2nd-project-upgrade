# ADR-010: Grafana 로그인 연동 방식

- 상태: Accepted (원안은 Keycloak OIDC였으나 SAML로 개정됨)
- 관련 파일: `25-grafana.tf`, `scripts/keycloak-grafana-saml-client.sh`, `scripts/grafana-dashboard-setup.sh`

## Context

보안 대시보드(Grafana)에 Keycloak SSO로 로그인하게 만들어야 했다. [ADR-005](ADR-005-human-approval-for-destructive-actions.md)
결정 3은 "온프레미스에 이미 있는 Grafana를 재사용해 신규 AWS 비용 없이
간다"는 전제였는데, 실제로는 온프레미스 Grafana가 준비되지 않은 상태였다.

## Decision

1. 온프레미스 Grafana 재사용 대신 Amazon Managed Grafana를 새로
   만든다 — 자체 EC2에 Grafana를 올려 서버 관리 부담을 지는 것보다
   관리형 서비스가 이 프로젝트의 다른 결정들(관리 부담 최소화)과 더
   맞는다고 판단했다.
2. **결정 7(원안)**: "Grafana 로그인은 Keycloak OIDC"로 최초 결정했었다.
3. **결정 7(개정)**: Amazon Managed Grafana는 임의 OIDC 프로바이더 직접
   연동을 지원하지 않고 SAML 2.0 직접 연동만 지원한다는 사실을 확인하고
   (AWS 공식 확인, Keycloak도 지원 목록에 명시), SAML로 구현하도록
   결정을 수정했다. [ADR-001](ADR-001-saml-temporary-credentials-for-humans.md)의 AWS IAM SAML Provider(`aws_iam_saml_provider.keycloak`)와는
   별개로, Grafana 전용 SAML 클라이언트를 Keycloak에 추가로 등록해야
   한다(`scripts/keycloak-grafana-saml-client.sh`, 수동 실행 단계 있음).

## Consequences / 알려진 한계

- Grafana 워크스페이스가 만들어져도 로그인이 바로 되지 않는다 — Keycloak에
  Grafana 전용 SAML 클라이언트를 별도로 등록하고, 그 메타데이터를
  Grafana 워크스페이스에 연결하는 수동 단계가 남아 있다.
- SAML 클라이언트 설정을 맞추는 과정에서 여러 차례 잘못된 진단을
  거쳤다 — 실제 원인과 최종 설정값은 [TROUBLESHOOTING.md](../../TROUBLESHOOTING.md)의
  "Grafana SAML 로그인 - 3차례 잘못된 진단 끝에 찾은 원인" 절 참고.
- 대시보드 프로비저닝(`scripts/grafana-dashboard-setup.sh`)에서도 API로
  만든 패널이 브라우저에서는 "미완성" 상태로 보이는 별개의 버그를
  겪었다 — 같은 TROUBLESHOOTING.md의 Grafana 절에 정리되어 있다.
