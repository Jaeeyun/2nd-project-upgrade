# 나중에 할 일 (Backlog)

지금 당장 급하지 않거나, 다운타임/서비스 영향 리스크가 있어 미룬 항목들을
모아둔 문서입니다. 코드 곳곳(`README.md`, `TROUBLESHOOTING.md`, 각 `.tf`
주석, [`docs/adr/`](adr/README.md))에 흩어져 있던 "다음 단계", "Track 4",
"미완성" 표시들을 여기 한 곳에 모았습니다. 실제로 손댈 때는 이 문서보다
먼저 각 항목이 가리키는 원본 파일을 다시 확인하세요 — 여기는 요약이고,
근거와 최신 상태는 원본에 있습니다.

## 1. 자격증명/설정값을 SSM Parameter Store · Secrets Manager로 이전

- **현재 상태**: `db_password`, `keycloak_test_users_password` 같은 실제
  비밀값이 `terraform.tfvars`(gitignore 처리됨, 로컬에만 존재)에 평문으로
  들어있습니다.
- **하고 싶은 것**: 사람이 값을 정해서 tfvars에 적어넣는 대신, Terraform이
  `random_password`로 값을 직접 생성해서 AWS Secrets Manager에 쓰게 만들기.
  이미 `keycloak-bootstrap.sh.tpl`이 admin 비밀번호를 SSM Parameter
  Store에서 읽어오는 패턴을 쓰고 있으니(Terraform이 SSM에 쓰고, 셸
  스크립트가 런타임에 읽는 구조), 같은 패턴을 db_password 등에도 확장.
- **왜 나중에**: 닭-달걀 문제 자체는 `random_password` 방식으로 없앨 수
  있지만, "비밀번호를 사람이 원하는 값으로 지정하고 싶다"는 요구와는
  트레이드오프가 있어 정책 결정이 먼저 필요함. CIDR 목록/담당자
  연락처/feature flag 같은 나머지 tfvars 값은 애초에 "비밀"이 아니라
  "환경 설정"이라 Secrets Manager로 옮겨도 보안상 이득이 크지 않음 —
  옮길 대상을 진짜 비밀값으로 한정해야 함.

## 2. K8s 보안 강화

- **PSA(Pod Security Admission)가 아직 audit 단계**: `34-k8s-namespaces-rbac.tf`가
  `baseline` 기준으로 위반을 감시만 하고 막지는 않음(POL-01). 충분한 관찰
  후 `enforce`로 전환 필요(POL-02) — [ADR-020](adr/ADR-020-psa-replaces-kyverno.md) 참고.
- **Kyverno 제거로 세밀한 admission 정책이 없음**: PSA는 baseline Audit
  수준의 표준 정책만 제공하고, 커스텀 admission 규칙(임의 조건)은 못
  만듦. 더 세밀한 정책이 필요해지면 재검토 필요.
- **Falco가 배포되지 않음**: [ADR-003](adr/ADR-003-guardduty-foundational-only.md)이 EKS/EC2 런타임 위협 탐지를
  Falco에 맡기기로 했지만, "EKS/EC2(K3s) 양쪽"이 전제인데 K3s 노드
  자체가 아직 없어 Falco 도입이 미뤄진 상태 — 지금은 컨테이너 런타임
  위협에 대한 실질적 탐지 공백이 있음.
- **`RoleSessionName` 위조 가능성 미해결**: `AssumeRoleWithSAML`을 직접
  호출하는 경로에서 `RoleSessionName`이 이론상 위조 가능하다는 한계가
  있음. `hr-backend` 접근 분리는 위조 불가능한 Role ARN 기반으로
  옮겼지만([ADR-019](adr/ADR-019-eight-role-structure.md)), K8s Access Entry의 `user_name`은 여전히
  `RoleSessionName`을 그대로 노출함 — 완전한 해소는 아님. 근본 해결은
  RoleSessionName에 `req{request_id}`를 붙이는 커스텀 Keycloak
  Authenticator SPI 개발이 필요함(README "설계상 트레이드오프" 참고).

## 3. Security Hub Track 4 (다운타임 리스크로 미룬 통제)

- **RDS.3 — RDS 저장 암호화 꺼짐**: 기존 인스턴스는 스냅샷 → 암호화
  스냅샷 → 새 인스턴스 복원 과정이 필요해 다운타임 발생.
  [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)의 "RDS 저장 암호화가 꺼져 있음" 절 참고.
- **ECR.2 — 이미지 태그 불변성(IMMUTABLE) 미적용**: `build-and-push.sh`가
  `:latest` 태그를 계속 재사용하는 방식이라, 태그 전략을 git SHA/타임스탬프
  기반으로 바꾸고 `deploy.sh`/k8s 매니페스트도 같이 고쳐야 하는 별도
  작업. `07-ecr.tf` 주석, TROUBLESHOOTING.md의 ECR 절 참고.
- **EC2.172 — VPC Block Public Access 미적용**: 계정/리전 전체의 IGW
  트래픽을 기본 차단하는 설정이라, Keycloak/Pomerium EC2와 NAT Gateway가
  실제로 인터넷과 통신 중인 지금 상태에서 그냥 켜면 즉시 서비스 장애.
  `aws_vpc_block_public_access_exclusion`으로 VPC별 예외를 먼저 만들어야
  함(`38-s3-security-hardening.tf` 주석 참고).
- **RDS.3와 함께 보류된 EC2.3 / EKS.2 / EKS.9 등**: 세션 초반에
  "다운타임 리스크가 있는 항목"으로 함께 Track 4 분류했던 나머지
  통제들 — 손대기 전에 Security Hub 콘솔에서 현재 상태와 정확한 통제
  설명을 다시 확인 필요(시간이 지나 번호/설명이 바뀌었을 수 있음).

## 4. 네트워크 경로 미검증

- **Keycloak VPC ↔ demo VPC 간 SG 미개방**: VPC Peering(`15-keycloak-vpc-peering.tf`)까지만
  구성되어 있고, EKS/RDS 보안그룹은 아직 Keycloak VPC의 CIDR을 허용하지
  않음 — 사설 라우팅은 연결돼 있지만 kubectl/psql이 실제로 이 경로로
  demo VPC 내부 자원에 도달하는지는 검증되지 않음.
- **Pomerium이 IP 기반 라우팅으로 잘 동작하는지 실제 미검증**: Pomerium은
  보통 도메인 기반 라우팅을 전제로 하는 도구라, 문제 생기면 가짜 도메인을
  `/etc/hosts`에 매핑하는 우회가 필요할 수 있음.

## 5. 인증서/암호화 관리

- **자체서명 인증서(PoC 전용)**: Keycloak, Pomerium, 내부 mTLS ALB 모두
  자체서명 CA를 씀. 정식 도입 시 ACM + ALB로 교체 필요.
- **mTLS 인증서 자동 갱신 없음**: `32-mtls-alb.tf`의 인증서 유효기간이
  30일이고 자동 갱신이 없음(의도적 결정 — AWS Private CA 월
  $50~400 비용 때문에 자체 CA 유지를 선택). 30일 넘게 계속 쓰려면
  `validity_period_hours`를 늘리거나 수동 재발급 필요.

## 6. 미완성으로 남아있는 자동화/검증

- **MFA 강제(REQUIRED 전환) 미완성**: 지금은 OTP 정책/브루트포스 방어만
  자동화되어 있고, "MFA 없이는 로그인 불가"로 만들려면 Keycloak 콘솔에서
  Authentication Flow를 직접 조정한 뒤 코드로 역산해야 함
  (`keycloak-bootstrap.sh.tpl` 6번 항목 주석 참고).
- ~~**ASR 리미디에이션 플레이북 0개 배포**~~ (2026-08-13 해결): member-roles/
  member 템플릿까지 배포 완료(`41-asr-member-remediation.tf`), `ASR-SC_2.0.0_EC2.13`
  런북 실제 동작 확인함([ADR-014](adr/ADR-014-asr-misconfiguration-remediation.md) 참고). `LoadSCMemberStack=yes`
  하나만 켜뒀으니, EC2.13 외 다른 control 런북이 필요해지면 그 파일의
  `LoadAFSBPMemberStack` 등 나머지 파라미터도 켜야 함.
- **EKS 파드 격리의 finding 필드 파싱 미검증**: `scripts/eks-pod-isolate.py`의
  `_extract_pod_info`가 실제 GuardDuty EKS finding 샘플로 검증되지 않음 —
  finding 종류마다 파드 이름/네임스페이스 필드 위치가 달라 "재확인 필요"로
  표시되어 있음.
- **`scripts/session-revoke.py`의 이벤트 필드 경로 미검증**: Security Hub
  Custom Action → EventBridge 경유 시 `RoleSessionName`을 어느 필드에서
  꺼내는지가 추정 경로("재확인 필요" 표시).
- **CI Role 권한이 아직 넓은 베이스라인 상태**: [ADR-007](adr/ADR-007-ciem-unused-access-cycle.md) 결정 1대로
  4주 관찰 후 실사용 데이터를 근거로 최소화해야 함 — 아직 관찰 기간이
  끝나지 않음.
- **GitHub Actions OIDC thumbprint 재확인**: `22-cicd-oidc.tf`에 하드코딩된
  thumbprint 값을 GitHub이 주기적으로 갱신할 수 있어, 다음 apply 전
  최신값을 GitHub 공식 문서에서 재확인 권장.
- **ASR 템플릿 URL/파라미터 재확인**: `asr_template_url`과
  `LoadAFSBPSolution` 등 CloudFormation 파라미터가 조사 시점 기준으로
  100% 확정되지 않음 — apply 전 AWS Solutions Library에서 최신값 확인
  권장.

## 우선순위에 대해

이 문서는 "무엇이 남았는지"를 모으기만 한 목록이라 순서를 매기지
않았습니다. 실제로 착수할 때는 영향 범위(다운타임 여부)와 현재 리스크
크기를 기준으로 다시 우선순위를 정하는 걸 권장합니다.
