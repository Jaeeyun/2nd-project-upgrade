# project-c HR 앱 실행 가이드

`terraform destroy` 후 `terraform apply`로 인프라를 다시 올렸을 때, 지금과 동일한 상태로
HR 앱(employee/hr 사이트)까지 복구하기 위한 순서입니다. Keycloak/Pomerium/RDS/ALB
target group은 재생성될 때마다 IP·ARN이 바뀌므로, 이 값들을 손으로 옮겨 적지 말고
`deploy.sh`가 매번 새로 조회하도록 만들어 뒀습니다.

---

## 0. 이 가이드가 다루는 범위

`~/project-c`의 Terraform(`00-versions.tf` ~ `36-*.tf`)이 관리하는 것들
(Keycloak/Pomerium EC2, mTLS ALB + target group 3개 + 리스너 규칙, EKS, RDS, ECR
저장소, 보안그룹, `34-k8s-namespaces-rbac.tf`가 만드는 네임스페이스 3개)은
`terraform apply` 한 번으로 복구됩니다. **이 가이드는 그 위에 필요한, Terraform이
관리하지 않는 나머지 부분**(Docker 이미지, ALB Controller, HR 앱 k8s 매니페스트,
RDS 시드 데이터, **DB 마스킹 뷰, Grafana 대시보드, Slack CIEM 연동 값**)을 다룹니다.

---

## 1. Terraform 인프라 적용

```bash
cd ~/project-c
terraform apply
```

`terraform.tfvars`에 `db_password`, `keycloak_admin_cidr`(관리자 PC의 공인 IP),
`keycloak_test_users_password`가 채워져 있는지 먼저 확인하세요.

완료까지 Keycloak 부트스트랩(realm/client/유저 생성) + `null_resource.wait_for_keycloak`
폴링 때문에 15분 가량 걸릴 수 있습니다.

---

## 2. kubeconfig 등록

```bash
aws eks update-kubeconfig --region ap-northeast-2 --name "$(cd ~/project-c && terraform output -raw eks_cluster_name)"
kubectl get nodes
```

---

## 3. AWS Load Balancer Controller 설치 (Helm)

TargetGroupBinding 동기화 전용입니다 — k8s Ingress로 새 ALB를 만들게 하면 Pomerium/mTLS를
우회하는 경로가 생기므로 **Ingress는 쓰지 않습니다** (32-mtls-alb.tf 주석 참고).

```bash
helm repo add eks https://aws.github.io/eks-charts
helm repo update

helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName="$(cd ~/project-c && terraform output -raw eks_cluster_name)" \
  --set serviceAccount.create=true \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="$(cd ~/project-c && terraform output -raw alb_controller_iam_role_arn)"

kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

파드 2개 다 `1/1 Running`이면 정상입니다.

---

## 4. Docker 이미지 빌드 & ECR push

```bash
cd ~/project-c/hr-app
./build-and-push.sh
```

ECR 저장소는 `terraform destroy` 시 안의 이미지까지 같이 삭제되므로
(`force_delete = true`), destroy/apply 사이클마다 다시 실행해야 합니다.

---

## 5. HR 앱 배포

```bash
cd ~/project-c/hr-app/k8s
./deploy.sh
```

이 스크립트가 매번 다시 조회해서 채우는 값들:

| 값 | 조회 방법 | 재생성 시 바뀌는 이유 |
|---|---|---|
| `DB_HOST` | `terraform output rds_endpoint` | RDS를 새로 만들면 엔드포인트 호스트명이 바뀜 |
| `POMERIUM_PRIVATE_IP` | `terraform state show aws_instance.pomerium` | Pomerium을 새로 만들면 사설 IP가 바뀜(JWT 검증용 JWKS URL에 씀) |
| `EMPLOYEE_TG_ARN` / `HR_TG_ARN` / `FRONTEND_TG_ARN` | `aws elbv2 describe-target-groups` | target group도 새로 생성되며 ARN이 바뀜 |

스크립트 끝에서 DB 마이그레이션/시드 Job을 실행하고(4명 테스트 계정 데이터 채움),
Deployment 롤아웃 완료까지 기다립니다.

---

## 6. DB 마스킹 뷰 적용 (`hr-data-masking-views.sql`)

⚠️ **`deploy.sh`가 자동으로 실행해주지 않습니다.** `deploy.sh`가 실행하는 `migrate.py`는
시드 데이터만 넣고, 마스킹 뷰(`masked.*`)와 IAM 인증용 DB Role(`general_user_readonly`
등) 생성/권한 부여는 이 SQL 스크립트가 별도로 담당합니다. 이 단계를 건너뛰면 씬 5(마스킹
확인)와 씬 9(마스킹 우회 자동 REVOKE)가 전부 실패합니다.

RDS가 프라이빗 서브넷에만 있어서 로컬에서 바로 psql 접속이 안 됩니다. `16-rds-isolated-access.tf`가
준비해 둔 격리 서브넷으로 CloudShell VPC 환경을 열어서 실행하세요(이 서브넷은 인터넷 경로가
없어 CloudShell 파일 유출 경로도 막혀 있습니다):

1. AWS 콘솔 → CloudShell → 우측 상단 VPC 환경 생성
   - VPC: `terraform output -raw vpc_id`로 확인한 이 프로젝트의 VPC
   - Subnet: `aws_subnet.rds_readonly_isolated` (terraform output `rds_readonly_isolated_subnet_id`)
   - Security group: `terraform output rds_readonly_cloudshell_sg_id`
2. CloudShell VPC 환경 안에서:

```bash
cd ~/project-c   # 이 리포를 CloudShell에도 올려뒀거나, hr-data-masking-views.sql만 업로드
psql -h "$(terraform output -raw rds_endpoint | cut -d: -f1)" \
     -U adminuser -d demodb -f hr-data-masking-views.sql
```

  (`adminuser`/`demodb`는 `01-variables.tf`의 `db_username`/`db_name` 기본값입니다.
  `terraform.tfvars`에서 바꿨다면 그 값을 쓰세요.) 비밀번호는 `terraform.tfvars`의
  `db_password` 값을 입력하면 됩니다.

3. 확인:

```sql
SET ROLE general_user_readonly;
SELECT * FROM masked.employees_general LIMIT 5;  -- salary가 NULL로 보여야 정상
RESET ROLE;
```

---

## 7. Grafana 대시보드 프로비저닝 (`scripts/grafana-dashboard-setup.sh`)

⚠️ 이것도 `terraform apply`가 자동으로 해주지 않습니다. 안 하면 씬 1~6/12/13에서
Grafana에 로그인은 되지만 대시보드가 비어 있습니다.

```bash
cd ~/project-c
GRAFANA_ENDPOINT=$(terraform output -raw grafana_workspace_endpoint)
KEYCLOAK_USER=test-ops-lead KEYCLOAK_PASSWORD='<keycloak_test_users_password 값>' \
  ./scripts/grafana-dashboard-setup.sh
```

완료 후 출력되는 `https://<endpoint>/d/soc-scene13` 링크로 접속해 4개 패널(Security Hub
findings, VPC Flow 거부, IAM API 타임라인, SSM 세션 로그)에 데이터가 뜨는지 확인하세요.
패널 4(SSM 세션 로그)가 브라우저에서 "No Data"로 보이면, 이 스크립트가 만든 패널을 삭제하고
Grafana UI에서 CloudWatch Logs 패널을 새로 만든 뒤 아래 쿼리를 직접 입력하는 게 더 안정적입니다
(API로 만든 패널이 프론트엔드 초기화 상태 문제로 가끔 안 열립니다):

```
fields @timestamp, userIdentity.arn as user_arn, sessionId, @message
| sort @timestamp desc
| limit 100
```

---

## 8. Slack CIEM 연동 값 재설정 (씬 11)

destroy 이력이 있다면(=Secrets Manager 시크릿이 재생성됐다면) 아래를 확인/재설정하세요.

**8-1. 시크릿 값이 플레이스홀더인지 확인:**

```bash
aws secretsmanager get-secret-value \
  --secret-id demo-project-dev-slack-app-credentials \
  --query SecretString --output text
```

`xoxb-여기에-실제-값을-채우세요`가 보이면 플레이스홀더 그대로인 것입니다([28-ciem-key-exception-flow.tf:29-38](../28-ciem-key-exception-flow.tf#L29-L38)의
`lifecycle.ignore_changes`는 *기존* 값을 보호할 뿐, destroy로 시크릿 자체가 사라진 뒤의
재생성까지는 못 막습니다). 실제 값으로 갱신:

```bash
aws secretsmanager put-secret-value \
  --secret-id demo-project-dev-slack-app-credentials \
  --secret-string '{"bot_token":"xoxb-실제값","signing_secret":"실제값"}'
```

**8-2. Slack App의 Interactivity Request URL 갱신:**

API Gateway는 destroy/apply마다 API ID가 새로 생성되어 URL이 바뀝니다. 새 URL 확인:

```bash
cd ~/project-c
terraform output -raw slack_interactivity_endpoint
```

이 값을 [api.slack.com/apps](https://api.slack.com/apps) → 해당 앱 → **Interactivity & Shortcuts**
→ Request URL에 붙여넣고 저장하세요(Slack이 즉시 한 번 ping을 보내 검증하므로, 이 단계 전에
Lambda가 정상 배포돼 있어야 성공합니다).

---

## 9. 접속 테스트

`deploy.sh` 마지막에 출력되는 Pomerium 퍼블릭 IP를 Windows PC의
`C:\Windows\System32\drivers\etc\hosts`(관리자 권한 편집)에 등록:

```
<IP>  employee.company.com
<IP>  hr.company.com
```

저장 후 관리자 권한 cmd에서 `ipconfig /flushdns`. 크롬의 "보안 DNS"가 켜져 있으면
hosts 파일을 무시할 수 있으니 `chrome://settings/security`에서 꺼두는 걸 권장합니다.

| 테스트 계정 | 접속 도메인 | 기대 결과 |
|---|---|---|
| `chulsoo.kim@company.com` / `younghee.lee@company.com` / `gildong.hong@company.com` | `employee.company.com` | 본인 정보만 |
| `minsu.park@company.com` (인사팀) | `hr.company.com` | 본인 제외 직원 목록, 등록/수정 가능 |

임시 비밀번호는 `terraform.tfvars`의 `keycloak_test_users_password` 값이며, 최초
로그인 시 비밀번호 변경 + TOTP(OTP) 설정이 강제됩니다.

---

## 10. Security Hub 위험 수용(Suppress) 처리

⚠️ 이것도 `terraform apply`가 해주지 않습니다. Security Hub finding은 Terraform
리소스가 아니라 계정 활동에 따라 동적으로 생성되는 대상이라, "정당한 사유로
고치지 않기로 한 항목"을 Suppressed 상태로 유지하려면 이 스크립트를 매번
다시 실행해야 합니다(멱등 - 몇 번을 실행해도 결과는 같습니다).

```bash
cd ~/project-c
./scripts/security-hub-suppress-accepted-risks.sh
```

아래 6개 카테고리(총 19건 - 2026-08-13 기준)를 찾아서 Suppress 처리하고 사유를 Note로
남깁니다. 안 하면 Security Hub 화면에 이 항목들이 계속 FAILED로 남아 있습니다.

| 카테고리 | Control ID | 사유 요약 |
|---|---|---|
| Slack webhook 인증 | APIGateway.8 | Slack 자체 HMAC 서명 검증(대체 통제 존재) |
| VPC 엔드포인트 미배포 | EC2.10, EC2.57 | NAT Gateway 경로로 이미 통제, 비용 대비 효과 낮음 |
| ASR 솔루션 내부 리소스 | DynamoDB.1 | AWS Solutions CFN 템플릿 소유, 우리 리소스 아님 |
| 유료 스캐너 미사용 | Inspector.1/2/4, GuardDuty.6/7/11 | 비용 대비 효과 낮음(PoC 규모) |
| 아키텍처 설계 | EC2.9, EKS.1 | Keycloak/Pomerium 퍼블릭 IP·EKS 퍼블릭 엔드포인트 모두 특정 CIDR로만 제한(보완 통제 존재) |
| 루트 계정 하드웨어 MFA | IAM.6 | 물리적 보안키 조달 제약, 위험 평가 후 수용(가상 MFA도 미등록 상태임을 Note에 명시) |

---

## 11. 알려진 미해결 항목 (의도적으로 Suppress하지 않음)

아래는 "위험 수용"이 아니라 **진짜 미해결 상태**로, 발표 대본에서도 "미완료"로
정직하게 표시해야 합니다.

| 항목 | Control ID | 상태 |
|---|---|---|
| EKS 클러스터 버전(1.31)/노드그룹 버전(1.30) 지원 종료 | EKS.2, EKS.9 | 발표 전 업그레이드는 다운타임 리스크가 있어 보류 - **발표 후 업그레이드 예정** |
| AWS Config 서비스 연결 역할 반영 지연 | Config.1 | 2026-08-13에 실제로는 이미 고쳐짐(`aws configservice describe-configuration-recorders`로 `AWSServiceRoleForConfig` 확인됨). Security Hub의 Config 기반 통제는 최대 24시간 주기로만 재평가되어 대시보드에 FAILED로 잠시 남아있을 수 있음 - **별도 조치 불필요, 자동 해소됨** |

---

## 자주 겪은 문제 요약

| 증상 | 원인 | 해결 |
|---|---|---|
| Keycloak/Pomerium 부트스트랩이 admin 토큰 발급에서 계속 실패 | `curl -d`가 비밀번호의 `+`를 URL 인코딩 안 해서 공백으로 깨짐 | `--data-urlencode` 사용 (이미 반영됨) |
| Pomerium 로그인 시 504 Gateway Timeout | 같은 VPC 안에서 서로의 퍼블릭 IP로 접근 시 hairpin으로 응답 없음 | 서버간 호출은 private IP, `idp_provider_url`은 AWS 기본 퍼블릭 DNS 이름(split-horizon) 사용 (이미 반영됨) |
| Keycloak 로그인 페이지에서 `Invalid redirect_uri` | Pomerium만 재생성돼도 IP가 바뀌는데 Keycloak의 OIDC 클라이언트 `redirectUris`가 갱신 안 됨 | pomerium-bootstrap.sh.tpl이 매 부팅 시 클라이언트를 재조회해서 갱신하도록 수정됨 (이미 반영됨) |
| 로그인 성공 후 403 `domain-unauthorized` | Pomerium PPL의 `domain.is: "*"`는 와일드카드가 아니라 리터럴 매치라 항상 거짓 | `allow_any_authenticated_user: true` 사용 (이미 반영됨) |
| employee/hr.company.com 접속 시 계속 echo 백엔드(mTLS ALB 더미) 응답만 나옴 | Pomerium이 업스트림에 보낼 때 Host 헤더를 원본이 아니라 자기 `to:` 주소로 덮어씀 | ALB 리스너 규칙을 `host-header`가 아니라 Pomerium이 항상 넣어주는 `X-Forwarded-Host`로 매칭 (이미 반영됨) |
| ALB target group이 계속 unhealthy (`Target.Timeout`) | EKS 노드가 `03-security.tf`의 `eks_nodes_sg`가 아니라 EKS 자동생성 클러스터 SG를 쓰고 있어, ALB SG에서 오는 트래픽이 막힘 | 클러스터 SG에 ALB SG를 명시적으로 허용하는 규칙 추가 (`32-mtls-alb.tf`, 이미 반영됨) |
| 로그인 계정을 바꿔도 이전 사용자 정보가 그대로 보임 | API 응답에 `Cache-Control`이 없어 브라우저가 이전 사용자 응답을 캐시 | 두 백엔드에 `Cache-Control: no-store` 미들웨어 추가 (이미 반영됨) |
| ModHeader로 다른 사람 이메일을 넣으면 그 사람 행세가 됨 (스푸핑) | 앱이 클라이언트가 보낼 수도 있는 평문 `X-Pomerium-Claim-Email` 헤더를 그대로 신뢰 | 앱이 위조 불가능한 서명된 `x-pomerium-jwt-assertion`을 Pomerium의 JWKS로 검증하도록 교체 (이미 반영됨) — Pomerium SG에 메인 VPC CIDR에서 오는 443도 허용해야 Pod가 JWKS에 닿음 |
| `terraform plan`에서 `user_data`가 16384바이트 초과 에러 | Keycloak/Pomerium 부트스트랩 스크립트에 주석을 계속 추가하다 EC2 user_data 한도를 넘김 | 주석을 압축해서 여유를 둠 - 앞으로 스크립트 수정 시 이 한도(16KB, 한글 주석은 UTF-8 기준 글자당 최대 3바이트)를 염두에 둘 것 |
| `ping employee.company.com`이 시간 초과 | 보안그룹이 ICMP는 안 열고 443 TCP만 허용 | `Test-NetConnection <도메인> -Port 443`으로 확인 (ping은 정상적으로 실패함) |
