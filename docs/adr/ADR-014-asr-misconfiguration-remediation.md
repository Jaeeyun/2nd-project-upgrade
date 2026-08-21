# ADR-014: 설정 오류 자동조치는 AWS ASR을 CloudFormation으로 배포

- 상태: Accepted (admin + member 스택 모두 배포 완료 — 아래 참고)
- 관련 파일: `27-asr-remediation.tf`, `41-asr-member-remediation.tf`, `29-eks-pod-isolation.tf`, `23-security-alerting.tf`

## Context

Security Hub가 탐지하는 설정 오류(예: 퍼블릭 S3 버킷, 암호화 미적용 등)를
매번 사람이 수동으로 고치는 대신, AWS가 공식 제공하는 "Automated Security
Response on AWS(ASR)" 솔루션을 재사용해 표준화된 자동조치 체계를
갖추기로 했다.

## Decision

1. AWS Solutions의 ASR admin 템플릿을 `aws_cloudformation_stack`으로
   감싸 배포한다(`27-asr-remediation.tf`) — 오케스트레이터(Step Functions)와
   설정 테이블만 만든다.
2. **(최초 결정, 오류로 판명)** 이 계정은 AWS Organizations를 쓰지 않으므로
   ([ADR-001](ADR-001-saml-temporary-credentials-for-humans.md)에서 프리티어 문제로 이미 기각) member-roles/member 템플릿은
   불필요하다고 판단했었다. **실제로는 틀린 판단이었다** — member 템플릿은
   cross-account 배포를 위한 것이 아니라 실제 remediation 런북(SSM
   Automation 문서) 자체를 담고 있어서, Organizations 유무와 무관하게
   admin 계정 자신도 "member 계정 1개"로 간주되어 반드시 같은 계정에
   따로 배포해야 한다. `41-asr-member-remediation.tf`가 이 결정을
   바로잡아 `automated-security-response-member-roles.template`과
   `automated-security-response-member.template`을 추가로 배포한다.
   admin 스택이 `LoadSCAdminStack=yes`로 떠 있으므로 member 쪽도
   `LoadSCMemberStack=yes`로 맞췄다 — "SC"(Security Control)는 Security
   Hub의 통합 control ID(예: EC2.13) 기준 런북 묶음으로, 예전 AFSBP
   전용 이름을 대체한 것.
3. 자동조치 실행 결과 알림은 [ADR-005](ADR-005-human-approval-for-destructive-actions.md) 결정 4가 만든 SNS 토픽을
   재사용한다(`23-security-alerting.tf`).
4. [ADR-013](ADR-013-runtime-threat-response-framework.md)(런타임 위협 대응)이 이 ADR의 "Security Hub Custom Action
   기반 자동조치"라는 틀을 확장해 파드 격리에도 적용한다
   (`29-eks-pod-isolation.tf`).

## Consequences / 알려진 한계

- member 스택 배포 후 `aws ssm list-documents`로 `ASR-SC_2.0.0_EC2.13`
  등 런북 문서가 실제로 생성된 것을 확인했다 — Security Hub Custom
  Action("ASRRemediation")을 누르면 이제 실제로 finding이 고쳐진다.
- `LoadSCMemberStack=yes` 하나만 켜뒀다(AFSBP/CIS/PCI/NIST는 `no`) — 다른
  표준의 런북이 필요해지면 `41-asr-member-remediation.tf`의 해당
  파라미터를 `yes`로 바꿔야 한다.
- `asr_template_url`과 CloudFormation 파라미터(`LoadAFSBPSolution` 등)는
  조사 시점 기준으로 100% 확정되지 않았다 — apply 전 AWS Solutions
  Library에서 최신 템플릿 URL과 정확한 파라미터명을 직접 확인해야 한다.
  값이 틀리면 CloudFormation 에러로 명확히 실패하므로 조용히 잘못
  동작할 위험은 없다.
