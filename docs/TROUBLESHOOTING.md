# 트러블슈팅 기록

이 문서는 개발/검증 과정에서 실제로 겪은 문제와 원인, 해결 방법을 시간순이 아니라
**주제별로** 정리한 기록입니다. 코드 안 주석은 "지금 왜 이렇게 되어 있는가"만
설명하도록 정리했고, "무엇을 겪고 어떻게 고쳤는가"라는 과거형 서술은 전부 이
문서로 옮겼습니다. 코드를 다시 건드릴 일이 생기면 여기서 같은 함정을 미리
확인하세요.

---

## 네트워킹

### VPC 라우팅 테이블: 인라인 route와 별도 aws_route 리소스 충돌
`02-vpc.tf`의 라우팅 테이블에 인라인 `route {}` 블록을 쓰면, 그 라우팅 테이블의
전체 라우트 목록을 해당 리소스가 통째로 관리하게 된다. 그런데
`15-keycloak-vpc-peering.tf`가 같은 라우팅 테이블에 피어링 라우트를 별도
`aws_route` 리소스로 얹는 방식이라, 인라인 route를 쓰면 그 피어링 라우트를
"설정에 없는 드리프트"로 오인해 `terraform apply` 때마다 삭제해버렸다 -
Keycloak/Pomerium ↔ EKS 간 연결이 끊기는 사고로 이어짐. 해결: 모든 라우트를
독립된 `aws_route` 리소스로 통일(`aws_route.public_igw`, `private_nat` 등).

### EKS NetworkPolicy가 조용히 무력화됨 (VPC CNI 설정)
`31-hr-app-network-policy.tf`(HR 격리), `29-eks-pod-isolation.tf`(파드 격리)의
NetworkPolicy 오브젝트가 K8s API에는 정상 생성되는데 실제 트래픽 차단이 전혀
안 되는 문제가 있었다. 원인: 클러스터가 EKS 관리형 addon이 아니라 자체 설치된
VPC CNI로 떠 있었고, 그 안의 네트워크 정책 강제 에이전트(aws-eks-nodeagent)가
`--enable-network-policy=false` 상태였음. K8s API 레벨에서는 아무 에러도 안 나서
발견하기 매우 어려웠고, EKS 파드 격리 시나리오를 실제로 실행해보고서야
데이터플레인에서 강제가 전혀 안 되고 있다는 걸 알게 됨. 해결:
`aws_eks_addon.vpc_cni`를 관리형 addon으로 전환하면서
`configuration_values`에 `enableNetworkPolicy=true`를 명시(`04-eks.tf`).

### `eks_nodes_sg`는 죽은 리소스
`03-security.tf`의 `aws_security_group.eks_nodes_sg`는 어떤 노드그룹에도 실제로
연결되어 있지 않다. EKS 노드는 이 SG 대신 EKS가 클러스터 생성 시 자동으로
만드는 클러스터 SG를 쓴다. 이 사실은 mTLS ALB(`32-mtls-alb.tf`)의 헬스체크가
`Target.Timeout`으로 계속 unhealthy가 나서 원인을 추적하다가 발견함 - ALB SG를
`eks_nodes_sg`가 아니라 실제 클러스터 SG(`aws_eks_cluster.main.vpc_config[0].cluster_security_group_id`)에
허용해줘야 했음. `eks_nodes_sg` 자체는 정리 대상이지만 destroy에 영향 없어
남겨둔 상태.

---

## Keycloak / SAML

### Keycloak 로그인 페이지 접근이 관리자 IP로만 제한돼 있던 문제
`keycloak_admin_cidr` 변수는 원래 "apply를 실행하는 관리자 PC" 하나만 허용하는
용도였는데, 이 Keycloak이 Grafana SAML 로그인 페이지 역할도 겸하고 있어서 다른
사람이 로그인하려 하면 이 CIDR 제한에 걸려 타임아웃이 났다. 필요에 따라
`0.0.0.0/0`으로 임시로 넓혔다가 다시 특정 IP로 좁히는 식으로 운용 중.

### session-revoke.py의 Keycloak admin 토큰 요청이 매번 실패하던 문제
Scene 10(세션 강제 종료) 검증 중 발견: AWS 쪽 Deny 정책 적용은 성공하는데
`keycloak_logged_out`이 항상 "HTTP Error 400: Bad Request"로 실패했다.
원인은 `_get_keycloak_admin_token()`이 form 본문을 `f"...password={admin_password}"`로
직접 문자열 조립하고 있었던 것 - `openssl rand -base64`로 생성되는 admin
비밀번호에 `+`가 섞이면(실제로 섞여 있었음) `application/x-www-form-urlencoded`
파서가 그걸 공백으로 해석해서 비밀번호가 깨진다. `pomerium-bootstrap.sh.tpl`에서
이미 한 번 겪었던 것과 같은 종류의 버그인데, 이 Lambda는 지금까지 실제
admin 비밀번호로 끝까지 호출해본 적이 없어서(Terraform apply 성공 여부만
확인하고 넘어감) 이번에 처음 발견됨. `urllib.parse.urlencode()`로 조립하도록
수정.

### Keycloak EC2가 의도치 않게 재생성된 사고 및 복구
`user_data_replace_on_change = true`가 걸려 있어서(`11-keycloak.tf`),
`keycloak-bootstrap.sh.tpl`을 고치면 다음 apply 때 인스턴스가 통째로
교체된다는 걸 알고 있어서 그 이후로는 항상 `-target`으로 관련 없는
리소스만 골라 apply했는데도, 다른 작업(Scene 9의 SNS 제거용 보안그룹 교체)
중 실행해둔 백그라운드 apply 하나가 실제로 Keycloak 인스턴스를 교체해버린
사고가 있었다(CloudTrail에 `TerminateInstances` 기록 확인, 정확한 원인
경로는 끝내 특정 못 함 - `-target`을 지정했는데도 왜 무관 리소스가
같이 바뀌었는지는 재현 못 함). 인스턴스가 교체되면 `user_data`(부트스트랩
스크립트)에 있는 것들은 자동으로 복구되지만(테스트 유저 8+1명, Realm,
Role 그룹 등), **부트스트랩 스크립트 밖에서 수동으로 해둔 것들은 전부
사라진다** - 이번에 실제로 날아간 것:
  - Grafana 전용 SAML 클라이언트 등록(`keycloak-grafana-saml-client.sh`는
    별도 스크립트라 user_data에 없음) → 재실행해서 복구.
  - Admin API로 직접 바꿔둔 값들(예: 테스트 계정의 `requiredActions` 비우기,
    영구 비밀번호 설정) → 부트스트랩이 만든 계정은 `UPDATE_PASSWORD`/
    `CONFIGURE_TOTP`가 다시 걸린 상태로 돌아오므로 다시 해줘야 함.
  - `eks_public_access_cidrs`에 하드코딩해둔 Keycloak 퍼블릭 IP(SSM
    RunCommand로 EKS에 접근하기 위한 허용목록, `43-demo-scenario-resources.tf`
    관련) → IP가 바뀌었으므로 새 IP로 갱신하고 `aws_eks_cluster.main` 재적용.

  복구 절차(재사용 가능한 체크리스트):
  1. `terraform apply -target=aws_instance.keycloak
     -target=null_resource.wait_for_keycloak
     -target=data.http.keycloak_saml_metadata
     -target=aws_iam_saml_provider.keycloak`로 IAM SAML Provider부터
     새 인스턴스 메타데이터로 동기화.
  2. `-target=aws_grafana_workspace_saml_configuration.keycloak`도 **별도로**
     재적용해야 한다 - 1번만 하면 IAM 쪽은 갱신되지만 Grafana 쪽 SAML 설정은
     옛날 메타데이터(옛 IP)를 계속 캐시해서 로그인 리다이렉트가 죽은 IP로
     감(실제로 이 단계를 빠뜨려서 한 번 더 헤맴).
  3. `scripts/keycloak-grafana-saml-client.sh`를 새 인스턴스에 SSM
     RunCommand로 재실행(Grafana 전용 SAML 클라이언트는 부트스트랩에 없음).
  4. Admin API로 필요한 테스트 계정의 `requiredActions`를 다시 비우고
     비밀번호를 영구로 재설정.
  5. `terraform.tfvars`의 `eks_public_access_cidrs`를 새 Keycloak IP로
     바꾸고 `-target=aws_eks_cluster.main` 재적용.
  6. 새 비밀번호로 로그인 시도 시 "Invalid user credentials"가 나면,
     비밀번호에 `+` 같은 URL 예약 문자가 섞여 있을 수 있다 - `curl --data`가
     아니라 `--data-urlencode`를 쓰고 있는지 확인(안 그러면 서버가 `+`를
     공백으로 해석해서 비밀번호가 깨짐 - Pomerium 쪽에서 이미 한 번 겪은
     것과 같은 종류의 버그, "Pomerium / 헤더 스푸핑" 절 참고).

---

## RDS

### `backup_retention_period` 변경이 반영 안 되는 문제
`apply_immediately`를 명시하지 않으면(기본값 false) RDS 백업 설정 변경이 다음
유지보수 시간까지 대기 상태로만 큐잉되고 실제로는 반영되지 않는다.
`terraform apply`가 성공해도 AWS 실측값(`aws rds describe-db-instances`)은
그대로였음. 데모 환경에서는 변경이 바로 반영돼야 검증 가능하므로
`apply_immediately = true`로 강제함(`06-rds.tf`).

### RDS 저장 암호화가 꺼져 있음 (미해결, Track 4)
`aws_db_instance.main`에 `storage_encrypted`가 없어서 저장 암호화가 꺼진 채로
운영 중이었다(Security Hub RDS.3). 기존 인스턴스는 스냅샷 → 암호화 스냅샷 →
새 인스턴스로 복원해야 암호화를 켤 수 있어 다운타임이 발생 - 발표 이후로
작업을 미룸.

### 권한 드리프트 점검 Lambda(30번 tf)가 REVOKE는 하는데 drift_count를 0으로 보고함
Scene 9(마스킹 뷰 우회 GRANT 탐지) 검증 중 재현: 일부러 `employees` 테이블에
직접 GRANT를 만든 뒤 Lambda를 호출하면, `relacl`로 확인하면 REVOKE는 실제로
일어났는데 Lambda 응답은 `drift_count: 0`을 반환했다 - 반복 재현됨. 원인은
두 가지가 겹쳐 있었다:
  1. `WHERE grantee = ANY(%s)`로 파이썬 리스트를 넘기는 psycopg2 배열 파라미터
     바인딩이, 이 Lambda가 쓰는 커뮤니티 psycopg2 Layer 조합에서는 매칭이 안
     됐다(수동 `psql`로 똑같은 SQL을 직접 치면 정상 동작해서 처음엔 원인이
     안 보였음). `IN %s`(튜플 어댑팅) 방식으로 바꿔서 해결.
  2. 더 크게 혼란을 준 진짜 원인은 따로 있었다: 이 Lambda가 VPC 안에 있는데
     보안그룹에 RDS(5432) 아웃바운드만 있고 SNS 알림용 443 아웃바운드가
     없었다. `sns.publish()`가 `ConnectTimeoutError`로 죽으면서(REVOKE 자체는
     이미 커밋된 뒤라 조치는 끝났지만) Lambda가 Unhandled 에러로 실패
     처리됐고, 겹쳐서 실행된 이전 호출들이 뒤늦게 REVOKE를 마치는 바람에
     "방금 만든 드리프트를 조회했더니 이미 없다"는 식의 재현이 꼬였다.
     최종적으로는 SNS를 아예 빼고(Lambda는 CloudWatch Logs에 구조화된 한
     줄만 남김), Grafana 알림 규칙이 그 로그를 감시해서 Slack으로 알리는
     구조로 바꿔서 근본적으로 해결(`scripts/grafana-alerting-setup.sh`) -
     이러면 이 Lambda의 SG는 RDS 외에는 아무것도 열 필요가 없어진다.

---

## CloudWatch Logs / KMS

### CloudTrail용 KMS 키 정책에 `kms:Encrypt*`가 빠졌던 문제
CloudTrail 로그를 KMS로 암호화(Security Hub CloudTrail.2)하면서 CloudWatch
Logs 연동(CloudTrail.5)도 같이 켰는데, 로그 그룹 생성이
`AccessDeniedException: The specified KMS key does not exist or is not allowed
to be used`로 계속 실패했다. 처음엔 키 정책 전파 지연으로 의심했으나, 재시도해도
동일하게 실패. 원인은 키 정책에 `kms:Decrypt*`/`kms:GenerateDataKey*`/
`kms:Describe*`만 넣고 `kms:Encrypt*`/`kms:ReEncrypt*`를 빠뜨린 것 -
`PutLogEvents`가 로그를 쓸 때 암호화 권한이 필요한데 그게 없었음. 해결:
CloudWatch Logs 서비스 프린시펄에 `kms:Encrypt*` 포함 5개 액션 전부 부여
(`08-cloudtrail.tf`).

---

## Security Hub / Config

### Security Hub 점수가 갑자기 크게 변하는 현상 (정상 동작)
AWS Config recorder를 커스텀 Role에서 서비스 연결 Role로 교체하는 등 Config
설정을 바꾸면, Config가 계정 내 모든 리소스를 처음부터 다시 평가하는 과정을
거친다. 이 재평가가 백그라운드로 진행되면서 Security Hub 통제(Control)들이
"아직 평가 안 됨" 상태에서 실제 PASS/FAIL로 하나씩 확정되기 때문에, 짧은
시간 안에 통과율이 크게(예: 45%→83%) 뛰거나, 이미 고친 항목의 finding이
`LastObservedAt`이 과거 시각인 채로 몇 시간 동안 안 사라지는 것처럼 보일 수
있다. 코드/실제 리소스가 맞는지는 `terraform plan`(No changes)과 AWS CLI
실측으로 확인하는 게 Security Hub 콘솔 스냅샷보다 신뢰할 수 있음.

### 유령(ghost) finding: 삭제된 리소스의 잔여 finding
EKS 노드그룹을 여러 번 교체하고 Keycloak/Pomerium을 재기동하는 과정에서, 이미
삭제된 EC2 인스턴스/보안그룹에 대한 Security Hub finding이 한동안 활성 상태로
남아있었다(예: IMDSv2 미설정 27건, SSH 제한 위반 10건 등 - 전부
`describe-instances`/`describe-security-groups`로 조회해보면 존재하지 않는
리소스였음). Security Hub가 리소스 소멸을 자동으로 감지해 finding을 Archived
처리하기까지 시간이 걸리는 정상 지연이며, 실제 조치가 필요한 문제가 아니다.

### IAM 사용자에 정책을 직접 첨부한 부트스트랩 계정 (`terraform-admin`, `dev-admin`)
Keycloak/SAML 연동이 서기 전 부트스트랩용, 그리고 비상시 접근용으로 콘솔에서
미리 만들어둔 IAM 사용자 2개가 있었다(각각 6개 정책 직접 첨부 / AdministratorAccess
직접 첨부) - Security Hub IAM.2 위반이면서 이 프로젝트의 SAML 임시자격증명
원칙과도 어긋남. 삭제하지 않고 유지하기로 하되(비상 접근 경로 보존), Group을
만들어 정책을 Group에 옮기고 사용자는 Group 멤버십만 갖도록 재구성함
(`37-iam-bootstrap-users-group-migration.tf`). `dev-admin`은 이 Terraform을
실행하는 세션 자신의 자격증명이라, Group 권한이 실제로 살아있는 걸 확인한
뒤에야 기존 직접 첨부 정책을 제거하는 순서로 진행함(순서를 반대로 하면 작업
도중 자기 자신의 접근 권한이 끊길 위험이 있음).

---

## Amazon Managed Grafana / Athena 대시보드

### 패널 4(CloudWatch Logs)가 브라우저에서만 "No Data"
API로 직접 쿼리하면 정상인데 실제 브라우저에서 열면 CloudWatch Logs 패널이
계속 "No data"였다. 브라우저 Query Inspector로 확인해보니
`/api/datasources/.../resources/accounts` 호출이 403으로 막혀 있었음 - 원인은
CloudWatch 로그 패널의 쿼리 에디터가 초기화 단계에서 크로스어카운트
관측성 계정 목록(`oam:ListSinks`)을 먼저 조회하는데, 이 권한이 없으면 그
사전조회가 실패하면서 그 뒤 실제 로그 쿼리 자체를 브라우저가 안 보낸다는
것. API로 직접 쿼리하면 이 사전조회 단계 자체를 안 거쳐서 이 권한 없이도
동작했던 것이라 API 테스트에서는 이 문제가 전혀 안 잡혔다. 해결:
`oam:ListSinks`/`oam:ListAttachedLinks` 권한을 Grafana Role에 추가.

이 문제를 고친 뒤에도 API(`/api/dashboards/db`)로 프로비저닝한 패널은
여전히 "No data"였다 - UI에서 직접 만든 정상 동작 패널과 diff해서 `logGroups`
배열의 각 항목에 `accountId` 필드가 빠져있는 게 차이였음(이 필드를 채워도
간헐적으로 "쿼리 입력창이 로딩만 뜨고 안 열리는" 프론트엔드 상태 문제가
남아있어, 최종적으로는 이 패널만 Grafana UI에서 직접 재구성하는 쪽으로
정리함 - `scripts/grafana-dashboard-setup.sh` 주석 참고).

### CloudWatch Logs Insights 쿼리 문법 실패
`sessionData.0`처럼 배열 인덱스에 dot 표기를 쓰거나 별칭(`as`)에 한글을 쓰면
쿼리 자체가 실행되지 않았다. `fields @timestamp, userIdentity.arn as user_arn,
sessionId, @message | sort @timestamp desc | limit 100`처럼 ASCII 별칭 +
단순 필드 접근으로 바꾸니 정상 동작.

### Athena/Glue/Lake Formation/S3 권한 사슬 (4단계 모두 별도로 필요)
Grafana에서 Athena 패널이 동작하려면 아래 4개 레이어 권한이 전부 있어야
하고, 하나라도 빠지면 그 레이어에서만 조용히/AccessDenied로 막힌다.
1. Athena API 권한(`athena:StartQueryExecution` 등)
2. Glue Data Catalog 읽기 권한(Athena가 스키마 조회할 때 별도로 필요)
3. Lake Formation 권한(Security Lake Glue DB는 Lake Formation으로 별도
   거버넌스가 걸려있어 IAM 정책만으로는 "Insufficient Lake Formation
   permission(s)"로 막힘)
4. S3 읽기(원본 로그)/쓰기(쿼리 결과, `athena-results/` 프리픽스) 권한 -
   쓰기 권한이 없으면 `StartQueryExecution`이 에러 없이 조용히 실패함
5. (CloudTrail 테이블처럼 버킷이 KMS로 암호화된 경우) `kms:Decrypt`/
   `kms:DescribeKey` - S3 읽기 권한만으로는 부족하다. 이게 빠지면 Athena가
   실제로 그 객체를 열어보려는 시점에서야 막혀서 브라우저에는 `User: ...
   is not authorized to perform: kms:Decrypt on resource: .../key/...`
   403이 그대로 노출된다(`25-grafana.tf`의 `grafana_datasources` 정책에
   대상 KMS 키 ARN을 명시적으로 추가해서 해결 - Access Analyzer Role에서
   RDS 드리프트 체크 때도 겪은 것과 동일한 패턴).

### Athena "primary" 워크그룹에 결과 출력 위치가 없던 문제
기본 생성된 "primary" 워크그룹은 `OutputLocation`이 비어있어 쿼리 실행 결과를
어디 쓸지 몰라 막혀 있었다. Security Lake가 자동 생성한 버킷 이름(난수 포함)을
`s3_bucket_arn` 출력에서 파싱해 지정.

### Athena 플러그인이 설치되지 않음
`aws_grafana_workspace`의 `data_sources = ["ATHENA"]`는 IAM 권한만 만들어줄
뿐 Athena 데이터소스 "플러그인" 자체는 설치하지 않는다(Grafana
`/api/plugins?type=datasource`로 확인하면 cloudwatch만 있고
grafana-athena-datasource가 없었음). `pluginAdminEnabled`를 워크스페이스
`configuration`에 켜야 플러그인 관리 API 자체가 열려서 설치할 수 있다.

### CloudTrail 글로벌 서비스 이벤트는 리전 폴더가 아니라 us-east-1 밑에 쌓임
IAM처럼 글로벌 서비스인 API 호출은 트레일의 홈 리전(ap-northeast-2)이 아니라
`us-east-1` 경로 밑에 로그가 쌓인다(`include_global_service_events` 기본
동작). Glue 테이블 `location`에서 리전 하위 폴더를 지정하지 않고
`CloudTrail/` 전체를 가리키게 해서 모든 리전(글로벌 서비스 포함)을 한
테이블에서 잡음.

### Grafana SAML 로그인 - 3차례 잘못된 진단 끝에 찾은 원인
`Login failed / Failed to determine the state of the SSO redirect` 오류를
해결하는 과정에서 두 번 잘못 짚었다: (1) `saml.client.signature=true`가
Grafana(요청을 서명하지 않는 SP)에게 서명을 요구하고 있었던 건 실제 원인이
맞았지만, (2) 그 다음 XML 네임스페이스 프리픽스(`ds:` vs `dsig:`)를 잘못
읽어서 인증서가 안 맞는 줄 알고 불필요하게 클라이언트별 인증서로 바꿨던 건
잘못된 진단이었음(나중에 원복). 최종 원인은 Keycloak SAML 클라이언트 설정
조합 문제였고, `saml.server.signature=true` + `saml.assertion.signature=true` +
`saml.client.signature=false` + `saml_force_name_id_format=true` + 필수
프로토콜 매퍼 4개 확인으로 해결됨(`scripts/keycloak-grafana-saml-client.sh`).

### 패널 1(High/Critical Findings 카운트)이 실제 활성 건수보다 훨씬 크게 나옴
Security Hub 콘솔/API로는 Workflow=NEW인 High/Critical finding이 3건뿐인데
Grafana 패널은 20을 보여준 사례. 원인이 두 가지 겹쳐 있었다.

1. **`sh_findings` 테이블은 "현재 상태" 테이블이 아니라 append-only
   이벤트 로그**다 - 같은 finding이 재평가되거나 워크플로 상태가 바뀔
   때마다(예: Suppress 처리) 기존 행을 갱신하는 게 아니라 새 행이
   계속 쌓인다. 그래서 나중에 Suppress한 finding이라도 그 이전에
   기록된 "New" 상태 행이 테이블에 그대로 남아있어서, 단순히
   `WHERE status NOT IN ('Resolved','Suppressed')`로만 필터링하면
   과거 상태 행까지 다 세어져 실제보다 훨씬 부풀려진 값이 나온다.
   해결: `ROW_NUMBER() OVER (PARTITION BY finding_info.uid ORDER BY
   time_dt DESC)`로 finding UID별 최신 행만 남긴 뒤 그 위에서 status를
   필터링해야 한다(`docs/grafana/grafana-soc-dashboard.json` 패널 1
   참고).
2. 위 방식으로 고쳐도 여전히 Security Hub 콘솔의 실시간 값보다 크게
   나올 수 있는데, 이건 **Security Lake의 수집 지연** 때문이다 -
   Security Hub에서 방금 Suppress한 finding의 상태변경이 Security
   Lake OCSF 테이블에 반영되기까지 시간이 걸려서(수집이 실시간이
   아니라 주기적 배치), 그 사이엔 예전 "New" 스냅샷이 여전히 "최신
   행"으로 남아있다. 코드로 고칠 수 있는 문제가 아니라 시간이 지나면
   자연히 수렴하는 정상 동작이다.

---

## ASR (Automated Security Response)

### 초기 배포 실패 원인들 (순서대로 발견)
1. `capabilities`에 `CAPABILITY_IAM`이 빠져 있었음 - 공식 예시 기준으로 추가.
2. 최초 버전에 `LoadAFSBPSolution` 같은 파라미터를 넣었으나, 실제 템플릿
   파라미터 이름은 버전에 따라 다르다(`LoadAFSBPAdminStack` 등) - 잘못된
   이름을 넣느니 비워서 템플릿 기본값을 쓰는 쪽이 안전해 제거함. 정확한
   파라미터 목록은 CloudFormation 콘솔에서 이 template_url로 "스택 생성"
   마법사를 열면 화면에 그대로 뜬다.
3. `AdminUserEmail` 필수 조건은 해결했지만, 그다음 "ReservedConcurrentExecutions가
   계정의 최소 여유 동시실행 수(10)보다 낮아진다"는 에러로 롤백됨 - Web UI
   관련 Lambda들이 계정 기본 Lambda 동시실행 할당량을 초과 요구하는 것으로
   보임. Service Quotas에서 "AWS Lambda 동시 실행" 할당량을 늘리거나(보통
   승인까지 몇 시간~하루), Web UI 자체를 꺼서 이 Lambda들이 아예 안
   만들어지게 하는 두 가지 우회가 있음 - 이 프로젝트는 후자 선택.
4. 할당량을 1000으로 올린 뒤에도 스택이 10초 만에 리소스 하나도 못 만들고
   `ROLLBACK_COMPLETE`로 떨어짐 - CloudFormation 이벤트가 최상위 스택
   이벤트 4개뿐이고 중첩 스택(nested stack) 이벤트가 전혀 없어서, 리소스
   생성 이전 단계(Web UI용 중첩 스택 자체의 사전 검증)에서 막히는 것으로
   추정됨(정확한 원인 문구는 `DescribeStackEvents`로도 안 나옴 - AWS 쪽의
   알려진 한계로 보임). `ShouldDeployWebUI=no`로 Web UI 자체를 꺼서
   우회(AdminUserEmail Rule도 같이 비활성화되고 예약 동시실행 Lambda도 아예
   안 만들어짐 - 할당량 문제의 근본 회피).
5. 위 실패들을 반복하는 과정에서 DynamoDB 테이블(삭제 방지 켜짐), IAM Role,
   로그 그룹 5개가 orphan으로 남아 `AWS::EarlyValidation::ResourceExistenceCheck`가
   같은 이름의 새 스택 생성을 막았다 - 전부 수동으로 삭제 후 재시도해서 해결.

### 오케스트레이터만 배포되고 실제 리미디에이션은 안 됨
admin 템플릿을 성공적으로 배포해도, 이는 오케스트레이터(관리 뼈대)일 뿐이다.
실제로 finding을 고쳐주는 리미디에이션 플레이북은 AWS 표준(AFSBP 등)별로
Service Catalog에서 별도로 제품을 launch해야 생긴다. 이 프로젝트는 현재
플레이북을 하나도 배포하지 않은 상태라(`servicecatalog scan-provisioned-products`
결과 0건), Security Hub에서 "Remediate with ASR" Custom Action을 눌러도
실제로는 아무것도 고쳐지지 않는다 - 플레이북까지 배포해야 완전히 동작한다.

---

## Pomerium / 헤더 스푸핑

### X-Pomerium-Claim-Email 스푸핑 취약점 발견 및 조치
브라우저에서 ModHeader 같은 확장으로 `X-Pomerium-Claim-Email` 헤더를 직접
조작해서 로그인 계정과 무관하게 남의 이메일로 위장할 수 있는 게 재현으로
확인됨(chulsoo로 로그인했는데 minsoo로 보이는 현상). 처음에는 Pomerium
설정의 `remove_request_headers`로 이 헤더를 라우트 단계에서 지우려 했으나,
Envoy 필터 순서상 route의 remove가 ext_authz(Pomerium 인증 모듈)가 헤더를
넣은 "뒤"에 한 번 더 실행되어 정상 헤더까지 구분 없이 지워버려서 로그인한
사용자도 401이 나는 부작용이 있었음. 최종 해결: 이 평문 헤더는 그대로 두고
(Pomerium이 계속 정확한 값으로 갱신하긴 함), 앱 쪽(`hr-app/*/app/auth.py`)이
위조 불가능한 서명된 `x-pomerium-jwt-assertion`을 Pomerium의 JWKS
(`/.well-known/pomerium/jwks.json`)로 직접 검증해서 이메일을 추출하도록
변경 - 평문 헤더는 신뢰의 근거로 쓰지 않음.

### Keycloak/Pomerium 부트스트랩 스크립트에서 겪은 문제들
- **자체서명 인증서에 SAN 없음**: Go(Pomerium이 이걸로 빌드됨)는 1.15부터
  인증서에 SAN(Subject Alternative Name)이 없으면 CN만으로는 인정하지 않는다
  ("x509: certificate relies on legacy Common Name field"로 거부) -
  Keycloak 인증서의 private/public IP와 퍼블릭 DNS 이름을 전부 SAN에 명시.
- **`docker exec`가 stdin을 기본 연결 안 함**: `kcadm.sh`에 heredoc으로 JSON을
  넘기는 부분이 전부 빈 문서로 처리되어 실패 - `docker exec -i`로 수정.
- **비밀번호의 `+`가 URL 인코딩 안 됨**: `curl -d`는 자동 URL 인코딩을 안 해서
  `openssl rand -base64`로 만든 비밀번호에 `+`가 있으면 공백으로 깨짐 -
  비밀번호 필드만 `--data-urlencode`로 전송.
- **같은 VPC 안 hairpin 문제**: Keycloak과 Pomerium이 같은 VPC/서브넷에
  있을 때 서로의 퍼블릭 IP로 서버간 호출(OIDC discovery, Admin API 등)을
  하면 응답 없이 타임아웃 - private IP로는 즉시 정상 응답. 서버간 호출은
  private IP, "브라우저가 보는 로그인 화면 주소"만 public IP/DNS로 분리해서
  해결(AWS 기본 제공 퍼블릭 DNS 이름은 같은 VPC 안에서 private IP로,
  밖에서는 public IP로 풀리는 split-horizon 특성을 활용).
- **Pomerium이 Keycloak 재생성을 못 따라감**: Pomerium은 자신의 OIDC
  클라이언트를 Keycloak에 최초 부팅 시 한 번만 등록하므로, Keycloak
  인스턴스가 재생성되면(IP/realm 내용이 바뀜) Pomerium도 함께 재생성돼야
  새 Keycloak에 재등록된다 - `user_data_replace_on_change = true`로 해결.
- **Pomerium이 Keycloak 준비 완료 전에 부팅을 마침**: `aws_instance.keycloak`
  리소스에만 의존하면 "EC2가 생성되기 시작함"만 보장되고 "Keycloak
  부트스트랩이 다 끝나 SSM에 최신 admin 비밀번호까지 저장됨"은 보장되지
  않는다 - 그 결과 Pomerium이 SSM에서 이전 Keycloak 인스턴스 때의 예전
  비밀번호를 읽어가 `invalid_user_credentials`로 실패하는 경우가 있었음.
  `null_resource.wait_for_keycloak`(SAML descriptor가 응답할 때까지 폴링)에
  의존하도록 수정.

---

## CIEM Slack 인터랙티브 콜백

### API Gateway가 base64 인코딩한 바디를 안 풀고 서명 검증해서 모든 Slack 클릭이 401
`scripts/ciem-key-exception-callback.py`가 처리하는 Slack Interactivity
콜백은 이 시스템 전체에서 Slack 버튼 클릭이 유일하게 도착하는 지점이다.
API Gateway HTTP API(payload_format_version=2.0)는
`application/x-www-form-urlencoded` 바디를 base64로 인코딩해서 넘기는데
(`event["isBase64Encoded"]=true`), 이걸 디코딩하지 않고 그대로 서명
검증에 쓰면 Slack이 원본(디코딩 전) 바디에 대해 서명한 값과 절대 일치하지
않아 서명 검증이 항상 실패한다. 알림 발송(Slack 메시지 도착)까지는
정상이라 겉보기엔 잘 동작하는 것처럼 보였지만, 실제 버튼 클릭에 대한
반응(액세스키 삭제, IAM 정책 축소 등)은 전부 401로 막혀있던 상태였다 -
실제 Slack 연동 테스트(진짜 서명된 요청)로만 발견 가능했던 문제. 해결:
`isBase64Encoded`일 때 `base64.b64decode` 후 서명 검증.

---

## ECR

### 이미지 태그 불변성(ECR.2)을 켜지 못하는 이유
`aws_ecr_repository`의 `image_tag_mutability`를 `IMMUTABLE`로 바꾸면 안전하지만,
`build-and-push.sh`가 항상 같은 태그(`:latest`)로 재배포하는 방식이라 즉시
깨진다(불변 태그는 같은 태그로 두 번 push할 수 없음). 태그 전략을 git
SHA/타임스탬프 기반으로 바꾸고 `deploy.sh`/k8s 매니페스트도 같이 수정해야
하는 별도 작업이라 보류 중(Track 4).
