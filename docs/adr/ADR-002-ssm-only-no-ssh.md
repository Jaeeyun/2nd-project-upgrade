# ADR-002: EC2 접속은 SSM Session Manager만, SSH 전면 금지

- 상태: Accepted
- 관련 파일: `04-eks.tf`, `11-keycloak.tf`, `13-session-logging.tf`, `keycloak-bootstrap.sh.tpl`, `pomerium-bootstrap.sh.tpl`, `policies/03,04,06-role-*.json.tpl`, `scripts/security-hub-suppress-accepted-risks.sh`

## Context

EC2 인스턴스(Keycloak, Pomerium, EKS 워커 노드)에 사람이 들어가야 할 때가
있다. SSH 키 배포/로테이션/유출 관리 부담과 감사 추적의 어려움 때문에, SSH
자체를 아예 열지 않고 SSM Session Manager로만 접속하게 하기로 했다.

## Decision

1. 모든 보안그룹에서 22번 포트(SSH) 인바운드 규칙을 만들지 않는다. 이는
   개별 리소스 설정이 아니라 "SG에 SSH 룰이 아예 없다"는 부재 자체로
   표현되는 결정이다.
2. EC2 인스턴스는 SSM 관리형 정책(`AmazonSSMManagedInstanceCore`)이 붙은
   전용 Instance Profile을 받는다([ADR-011](ADR-011-dedicated-least-privilege-roles.md)과 결합).
3. EKS 워커 노드도 동일 원칙을 적용한다 — 원래는 SSM 없이 뒀었지만(쿠버네티스
   운영에서는 노드 셸에 들어갈 일이 드물다는 판단), 노드 자체 장애(디스크
   꽉 참, kubelet 다운 등) 대응용 비상 접속 경로로 나중에 추가했다.
4. **결정 5**: Session Manager Preferences는 기본적으로 세션 로깅이
   꺼져 있으므로, S3 + CloudWatch 로깅을 커스텀 SSM 문서로 강제
   활성화한다(`13-session-logging.tf`).
5. **결정 6**: 그 커스텀 문서 이름은 `SSM-SessionManagerRunShell`로
   고정한다 — IAM 정책(`policies/03,04,06-role-*.json.tpl`)의
   `AllowSSMSessionDocument` 문이 이 이름을 하드코딩해서 참조하므로, 이름을
   바꾸면 세션 자체가 안 열린다.

## Consequences / 알려진 한계

- Keycloak/Pomerium EC2는 여전히 퍼블릭 서브넷에 있다 — 네트워크 계층에서는
  인터넷에 노출되어 있고, 이 결정이 막는 것은 "SSH라는 접근 경로" 하나뿐이다
  (HTTPS 자체는 admin CIDR로 별도 필터링).
- Security Hub의 SSH 관련 통제(예: EC2.13 유사 항목)는 이 결정 덕분에
  대부분 자연히 통과하지만, 그렇다고 SG 자체가 완전히 폐쇄적인 건 아니다.
- SSM Session Manager 자체 가용성에 접속이 전적으로 의존한다.
