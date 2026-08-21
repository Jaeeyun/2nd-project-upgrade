# =============================================================================
# Amazon Managed Grafana (ADR-005 결정 3, ADR-010)
# =============================================================================
# ADR-010 결정 7은 원래 "Grafana 로그인은 Keycloak OIDC"라고 했지만, Amazon
# Managed Grafana는 임의 OIDC 프로바이더 직접 연동은 지원하지 않고 SAML 2.0
# 직접 연동만 지원한다(AWS 공식 확인, Keycloak도 지원 목록에 명시적으로 포함).
# 그래서 이 부분만 ADR-010을 수정하는 셈 치고 SAML로 구현한다 - AWS IAM SAML
# Provider(ADR-001의 aws_iam_saml_provider.keycloak)와는 별개로, Grafana 전용
# SAML 클라이언트를 Keycloak에 추가로 등록해야 한다(수동 작업, keycloak-bootstrap
# 스크립트에 추가 권장).
#
# 온프레미스에 아직 실제 Grafana가 없는 상태라, ADR-005 결정 3("온프레미스
# Grafana 재사용, 신규 AWS 비용 없음")과 달리 이번엔 Amazon Managed Grafana로
# AWS 쪽에 새로 만든다 - 자체 EC2에 Grafana를 올려서 서버 관리 부담을 지는 것보다
# 관리형 서비스가 이 프로젝트의 다른 결정들(관리 부담 최소화)과 더 잘 맞는다.

resource "aws_iam_role" "grafana" {
  name = "${local.name_prefix}-grafana-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "grafana.amazonaws.com" }
    }]
  })
}

# 대시보드 4개 데이터소스(CloudWatch/Athena) 조회 권한만 - 쓰기 권한 없음
data "aws_iam_policy_document" "grafana_datasources" {
  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:DescribeAlarmsForMetric",
      "cloudwatch:DescribeAlarmHistory",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:ListMetrics",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetInsightRuleReport",
      "logs:DescribeLogGroups",
      "logs:GetLogGroupFields",
      "logs:StartQuery",
      "logs:StopQuery",
      "logs:GetQueryResults",
      "logs:GetLogEvents",
      # CloudWatch 패널 쿼리 에디터는 초기화 단계에서 크로스어카운트 관측성
      # 계정 목록(oam:ListSinks)을 먼저 조회한다 - 이 권한이 없으면 그 뒤
      # 실제 로그 쿼리 자체를 브라우저가 보내지 않는다(API 직접 호출은 이
      # 사전조회를 거치지 않아 이 권한 없이도 정상 동작하므로 API 테스트만
      # 으로는 이 문제가 안 드러남).
      "oam:ListSinks",
      "oam:ListAttachedLinks",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "athena:GetDataCatalog",
      "athena:GetDatabase",
      "athena:GetTableMetadata",
      "athena:ListDatabases",
      "athena:ListTableMetadata",
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution",
      "athena:GetWorkGroup",
      "athena:ListWorkGroups",
    ]
    resources = ["*"]
  }

  # Athena가 Glue Data Catalog에서 스키마를 조회하려면 Athena API 권한과
  # 별개로 Glue 자체 읽기 권한이 필요하다.
  statement {
    effect = "Allow"
    actions = [
      "glue:GetDatabase",
      "glue:GetDatabases",
      "glue:GetTable",
      "glue:GetTables",
      "glue:GetPartition",
      "glue:GetPartitions",
      "glue:BatchGetPartition",
    ]
    resources = ["*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::aws-security-data-lake-*", "arn:aws:s3:::aws-security-data-lake-*/*"]
  }

  # 패널 3(CloudTrail Athena 테이블)이 가리키는 CloudTrail 원본 버킷은
  # Security Lake 버킷과 별개라 읽기 권한을 따로 부여해야 한다.
  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.cloudtrail_bucket.arn, "${aws_s3_bucket.cloudtrail_bucket.arn}/*"]
  }

  # Athena 쿼리 실행 결과를 쓸 S3 쓰기 권한도 필요하다(읽기 권한만 있으면
  # StartQueryExecution이 AccessDenied 없이 조용히 실패함). Security Lake
  # 버킷 안 athena-results/ 프리픽스로 범위를 한정.
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::aws-security-data-lake-*/athena-results/*"]
  }

  # [실제 검증 중 발견] CloudTrail 버킷 객체가 KMS로 암호화돼 있어서
  # (08-cloudtrail.tf) S3 읽기 권한만으로는 부족하다 - Athena가 그 객체를
  # 실제로 열어보려면 kms:Decrypt가 필요한데 이게 빠져 있으면 Grafana
  # 콘솔에 "kms:Decrypt on resource: .../key/..." 403으로 그대로 노출된다
  # (30-rds-permission-drift-check.tf의 Access Analyzer Role에서 겪은 것과
  # 동일한 패턴 - TROUBLESHOOTING.md 참고).
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [aws_kms_key.cloudtrail.arn]
  }
}

resource "aws_iam_role_policy" "grafana_datasources" {
  name   = "grafana-datasources-readonly"
  role   = aws_iam_role.grafana.id
  policy = data.aws_iam_policy_document.grafana_datasources.json
}

# Security Lake가 만드는 Glue 데이터베이스는 Lake Formation으로 별도
# 거버넌스가 걸려있어서, IAM 정책(glue:GetDatabase 등)만으로는 접근할 수
# 없고 Lake Formation 권한을 추가로 부여해야 한다.
resource "aws_lakeformation_permissions" "grafana_database" {
  principal   = aws_iam_role.grafana.arn
  permissions = ["DESCRIBE"]

  database {
    name = "amazon_security_lake_glue_db_${replace(var.aws_region, "-", "_")}"
  }
}

resource "aws_lakeformation_permissions" "grafana_tables" {
  principal   = aws_iam_role.grafana.arn
  permissions = ["SELECT", "DESCRIBE"]

  table {
    database_name = "amazon_security_lake_glue_db_${replace(var.aws_region, "-", "_")}"
    wildcard      = true
  }
}

# ---------- 대시보드 패널: IAM API 호출 타임라인용 CloudTrail Athena 테이블 ----------
# Security Lake의 CLOUD_TRAIL_MGMT 소스는 이 계정/리전 조합에서 미지원이라,
# 08-cloudtrail.tf가 만드는 일반 CloudTrail S3 버킷을 Athena 외부 테이블로
# 직접 매핑한다(AWS 공식 "CloudTrail 로그용 Athena 테이블 생성" 가이드의
# 표준 CloudTrailSerde 스키마 그대로).
resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "demo_project_cloudtrail_logs"
  database_name = "default"
  table_type    = "EXTERNAL_TABLE"

  storage_descriptor {
    # IAM처럼 글로벌 서비스인 API는 우리 리전(ap-northeast-2)이 아니라
    # us-east-1 경로 밑에 로그가 쌓인다(include_global_service_events 기본
    # 동작) - 리전 하위 폴더를 지정하지 않고 CloudTrail/ 전체를 가리켜서
    # 모든 리전(글로벌 서비스 포함)을 한 테이블에서 다 잡는다.
    location      = "s3://${aws_s3_bucket.cloudtrail_bucket.id}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,userName:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalId:string,arn:string,accountId:string,userName:string>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountId:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "apiversion"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "serviceeventdetails"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
  }
}

resource "aws_lakeformation_permissions" "grafana_default_database" {
  principal   = aws_iam_role.grafana.arn
  permissions = ["DESCRIBE"]

  database {
    name = "default"
  }
}

resource "aws_lakeformation_permissions" "grafana_cloudtrail_table" {
  principal   = aws_iam_role.grafana.arn
  permissions = ["SELECT", "DESCRIBE"]

  table {
    database_name = "default"
    name          = aws_glue_catalog_table.cloudtrail.name
  }
}

resource "aws_grafana_workspace" "main" {
  name                     = "${local.name_prefix}-soc"
  account_access_type      = "CURRENT_ACCOUNT"
  authentication_providers = ["SAML"]
  permission_type          = "SERVICE_MANAGED"
  role_arn                 = aws_iam_role.grafana.arn
  data_sources             = ["CLOUDWATCH", "ATHENA"]

  # data_sources 인자는 IAM 권한만 만들어줄 뿐, Athena 데이터소스 "플러그인"
  # 자체는 설치하지 않는다 - pluginAdminEnabled를 켜야 플러그인 관리 API가
  # 열려서 grafana-athena-datasource 플러그인을 설치할 수 있다.
  configuration = jsonencode({
    unifiedAlerting = { enabled = false }
    plugins         = { pluginAdminEnabled = true }
  })
}

# Grafana 전용 Keycloak SAML 클라이언트(scripts/keycloak-grafana-saml-client.sh)는
# aws_grafana_workspace.main의 엔드포인트(AWS가 배정하는 난수 ID 포함)가 있어야
# entityId/ACS URL을 만들 수 있어서 keycloak-bootstrap.sh.tpl(EC2 최초 부팅
# user_data)에는 못 넣었다. 예전에는 이걸 "terraform apply → 엔드포인트 확인 →
# 스크립트 수동 SSM 실행 → terraform apply 재실행" 수동 2단계로 했는데,
# null_resource + local-exec(scripts/tf-run-ssm-script.sh가 SSM RunCommand로
# 원격 실행)로 자동화해서 한 번의 apply로 끝나게 한다.
resource "null_resource" "keycloak_grafana_saml_client" {
  depends_on = [null_resource.wait_for_keycloak, aws_grafana_workspace.main]

  triggers = {
    grafana_endpoint     = aws_grafana_workspace.main.endpoint
    keycloak_instance_id = aws_instance.keycloak.id
    script_hash          = filemd5("${path.module}/scripts/keycloak-grafana-saml-client.sh")
  }

  provisioner "local-exec" {
    command = "${path.module}/scripts/tf-run-ssm-script.sh ${aws_instance.keycloak.id} ${var.aws_region} ${path.module}/scripts/keycloak-grafana-saml-client.sh GRAFANA_ENDPOINT=${aws_grafana_workspace.main.endpoint}"
  }
}

# Grafana SAML은 aws_grafana_workspace_saml_configuration이 idp_metadata_xml을
# 직접 받아 콘솔 수동 연결 없이 Terraform만으로 구성된다. Keycloak에는 이
# 워크스페이스 전용 SAML 클라이언트(entityId=https://<endpoint>/saml/metadata,
# ACS=.../saml/acs)와 role/email/login 속성 매퍼 3개를 위 null_resource가
# 자동 등록한다. IdP 메타데이터는 11-keycloak.tf의 data.http.keycloak_saml_metadata를
# 재사용한다(realm 전체 SAML descriptor라 AWS SAML Provider와 공용 가능).
# Amazon Managed Grafana는 관리형 서비스라 우리 VPC 안 메타데이터 URL을 직접
# 못 당겨오므로(Keycloak SG가 admin_cidr로만 열려있음) idp_metadata_url이
# 아니라 이미 가져온 idp_metadata_xml 문자열로 넘긴다.
resource "aws_grafana_workspace_saml_configuration" "keycloak" {
  workspace_id     = aws_grafana_workspace.main.id
  idp_metadata_xml = data.http.keycloak_saml_metadata.response_body

  role_assertion  = "role"
  email_assertion = "email"
  login_assertion = "login"
  name_assertion  = "name"

  # role 속성값은 Keycloak 그룹 이름 그대로 전송됨(grafana-role 매퍼,
  # saml-group-membership-mapper). ADR-019 8-Role 중 리드 2종만 관리자로.
  admin_role_values  = ["dev-lead", "ops-lead", "db-lead"]
  editor_role_values = ["dev-general", "ops-general", "db-general", "security-auditor", "dev-hr-backend"]

  depends_on = [null_resource.keycloak_grafana_saml_client]
}

# ---------- 표준(엔터프라이즈) SOC 대시보드 자동 프로비저닝 ----------
# 출처: AWS 공식 블로그 "Detect and respond to security threats in near
# real-time using Amazon Managed Grafana"가 제공하는 참조 대시보드
# (SecurityHub-v3.json, https://d2908q01vomqb2.cloudfront.net/artifacts/MTBlog/cloudops-1319/SecurityHub-v3.json)의
# 10개 패널 구성을 우리 Security Lake OCSF 스키마(sh_findings)에 맞게 remap한
# docs/grafana/grafana-securityhub-standard-dashboard.json을 그대로 배포한다.
# scripts/grafana-dashboard-setup.sh는 SAML 로그인 + 서비스 계정 토큰 발급 +
# 데이터소스 생성까지 전부 멱등하게 처리하므로 여러 번 재실행해도 안전하다.
# Grafana 로그인이 워크스페이스/SAML 클라이언트 전파 타이밍에 따라 일시적으로
# 실패할 수 있어 재시도 루프를 둔다.
resource "null_resource" "grafana_securityhub_standard_dashboard" {
  depends_on = [
    aws_grafana_workspace_saml_configuration.keycloak,
    aws_iam_role_policy.grafana_datasources,
    null_resource.keycloak_grafana_saml_client,
  ]

  triggers = {
    dashboard_hash   = filemd5("${path.module}/docs/grafana/grafana-securityhub-standard-dashboard.json")
    grafana_endpoint = aws_grafana_workspace.main.endpoint
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}
      export GRAFANA_ENDPOINT="${aws_grafana_workspace.main.endpoint}"
      export KEYCLOAK_ENDPOINT="${aws_lb.keycloak.dns_name}"
      export KEYCLOAK_USER="test-ops-lead"
      export KEYCLOAK_PASSWORD="${var.keycloak_test_users_password}"
      export DASHBOARD_JSON="docs/grafana/grafana-securityhub-standard-dashboard.json"
      for i in $(seq 1 10); do
        if bash scripts/grafana-dashboard-setup.sh; then
          echo "표준 대시보드 프로비저닝 성공"
          exit 0
        fi
        echo "대시보드 프로비저닝 실패, 15초 후 재시도... ($i/10)"
        sleep 15
      done
      echo "표준 대시보드 프로비저닝 최종 실패" >&2
      exit 1
    EOT
  }
}

output "grafana_workspace_endpoint" {
  value = aws_grafana_workspace.main.endpoint
}

output "grafana_workspace_id" {
  value = aws_grafana_workspace.main.id
}

output "grafana_saml_configuration_status" {
  value = aws_grafana_workspace_saml_configuration.keycloak.status
}

# Athena "primary" 워크그룹은 쿼리 결과 출력 위치(OutputLocation)가 비어있으면
# StartQueryExecution이 성공해도 결과를 어디 쓸지 몰라 조용히 막힌다. 버킷
# 이름은 Security Lake가 난수를 붙여 자동 생성하므로(aws_s3_bucket 등으로
# 직접 관리하지 않음) s3_bucket_arn 출력에서 파싱해서 쓴다.
resource "aws_athena_workgroup" "primary" {
  count = var.enable_security_lake ? 1 : 0
  name  = "primary"

  configuration {
    # 계정 공용 워크그룹이라 다른 용도의 쿼리까지 이 설정 강제 적용하지 않도록
    # enforce_workgroup_configuration은 기존 상태(false) 그대로 유지.
    enforce_workgroup_configuration = false

    result_configuration {
      output_location = "s3://${split(":::", aws_securitylake_data_lake.main[0].s3_bucket_arn)[1]}/athena-results/"
    }
  }
}

resource "null_resource" "grafana_cspm_interactive_dashboard" {
  depends_on = [
    aws_grafana_workspace_saml_configuration.keycloak,
    aws_iam_role_policy.grafana_datasources,
    null_resource.keycloak_grafana_saml_client,
  ]

  triggers = {
    dashboard_hash   = filemd5("${path.module}/docs/grafana/grafana-cspm-interactive-dashboard.json")
    grafana_endpoint = aws_grafana_workspace.main.endpoint
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}
      export GRAFANA_ENDPOINT="${aws_grafana_workspace.main.endpoint}"
      export KEYCLOAK_ENDPOINT="${aws_lb.keycloak.dns_name}"
      export KEYCLOAK_USER="test-ops-lead"
      export KEYCLOAK_PASSWORD="${var.keycloak_test_users_password}"
      export DASHBOARD_JSON="docs/grafana/grafana-cspm-interactive-dashboard.json"
      for i in $(seq 1 10); do
        if bash scripts/grafana-dashboard-setup.sh; then
          echo "CSPM 인터랙티브 대시보드 프로비저닝 성공"
          exit 0
        fi
        echo "대시보드 프로비저닝 실패, 15초 후 재시도... ($i/10)"
        sleep 15
      done
      echo "CSPM 인터랙티브 대시보드 프로비저닝 최종 실패" >&2
      exit 1
    EOT
  }
}

# 위 CSPM 인터랙티브 대시보드는 "언제 무슨 예외가 등록/억제됐는지" 시간순
# 감사 로그 위주라, 자원 하나에 finding이 여러 개 걸리는 경우(예: S3 버킷
# 하나가 서로 다른 컨트롤 10여 개에 동시에 걸림) 목록이 금방 지저분해진다.
# 그래서 "자원 관점" 탐색은 별도 대시보드로 분리했다 - 상단 변수(서비스/
# 리소스 ARN)로 좁혀서 위(자원별 롤업 요약) → 아래(선택한 자원의 finding
# 상세) 드릴다운 구조.
resource "null_resource" "grafana_cspm_resource_explorer_dashboard" {
  depends_on = [
    aws_grafana_workspace_saml_configuration.keycloak,
    aws_iam_role_policy.grafana_datasources,
    null_resource.keycloak_grafana_saml_client,
  ]

  triggers = {
    dashboard_hash   = filemd5("${path.module}/docs/grafana/grafana-cspm-resource-explorer-dashboard.json")
    grafana_endpoint = aws_grafana_workspace.main.endpoint
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}
      export GRAFANA_ENDPOINT="${aws_grafana_workspace.main.endpoint}"
      export KEYCLOAK_ENDPOINT="${aws_lb.keycloak.dns_name}"
      export KEYCLOAK_USER="test-ops-lead"
      export KEYCLOAK_PASSWORD="${var.keycloak_test_users_password}"
      export DASHBOARD_JSON="docs/grafana/grafana-cspm-resource-explorer-dashboard.json"
      for i in $(seq 1 10); do
        if bash scripts/grafana-dashboard-setup.sh; then
          echo "CSPM 자원 탐색기 대시보드 프로비저닝 성공"
          exit 0
        fi
        echo "대시보드 프로비저닝 실패, 15초 후 재시도... ($i/10)"
        sleep 15
      done
      echo "CSPM 자원 탐색기 대시보드 프로비저닝 최종 실패" >&2
      exit 1
    EOT
  }
}

# platform-grafana/ 아래 7개는 CSPM/CIEM 보안 대시보드가 아니라 범용 인프라
# 관측(EC2/RDS/EKS/ALB/NAT 등, Tier1~3 계층 구조) 대시보드다. 전부
# InstanceId/ClusterName/LoadBalancer 같은 dimension을 와일드카드(*)로 써서
# 특정 다른 환경에 고정돼 있지 않고, $env(dev/prod)/$region 변수만 맞으면
# 이 계정에 실제 있는 리소스를 그대로 잡아온다 - 그래서 새 파일/코드 없이
# 기존 grafana-dashboard-setup.sh 하나로 7개 다 순회 배포한다.
resource "null_resource" "grafana_platform_dashboards" {
  for_each = fileset("${path.module}/platform-grafana", "*.json")

  depends_on = [
    aws_grafana_workspace_saml_configuration.keycloak,
    aws_iam_role_policy.grafana_datasources,
    null_resource.keycloak_grafana_saml_client,
  ]

  triggers = {
    dashboard_hash   = filemd5("${path.module}/platform-grafana/${each.value}")
    grafana_endpoint = aws_grafana_workspace.main.endpoint
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}
      export GRAFANA_ENDPOINT="${aws_grafana_workspace.main.endpoint}"
      export KEYCLOAK_ENDPOINT="${aws_lb.keycloak.dns_name}"
      export KEYCLOAK_USER="test-ops-lead"
      export KEYCLOAK_PASSWORD="${var.keycloak_test_users_password}"
      export DASHBOARD_JSON="platform-grafana/${each.value}"
      for i in $(seq 1 10); do
        if bash scripts/grafana-dashboard-setup.sh; then
          echo "${each.value} 프로비저닝 성공"
          exit 0
        fi
        echo "${each.value} 프로비저닝 실패, 15초 후 재시도... ($i/10)"
        sleep 15
      done
      echo "${each.value} 프로비저닝 최종 실패" >&2
      exit 1
    EOT
  }
}