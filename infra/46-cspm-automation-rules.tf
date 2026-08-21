# =============================================================================
# Security Hub Automation Rules - 노이즈 1차 억제(평가 즉시 SUPPRESSED)
# =============================================================================
# scripts/security-hub-suppress-accepted-risks.sh는 "이미 쌓인 finding"을
# 한 번 훑어서 정리하는 스크립트라, 그 이후 새로 생기는 같은 유형의 finding엔
# 매번 다시 스크립트를 돌려야 한다. Automation Rules는 Security Hub가 finding을
# 평가하는 그 순간 조건에 맞으면 즉시 SUPPRESSED로 처리해서, 같은 유형의
# 위험 수용 항목이 반복적으로 Slack까지 도달하는 걸 원천 차단한다.
#
# rule_order가 낮을수록 먼저 평가된다 - 두 규칙 다 45번 파일의 EventBridge
# 필터보다 앞서 적용되므로(Security Hub 자체 파이프라인 단계), SUPPRESSED로
# 바뀐 finding은 RecordState는 그대로 ACTIVE라도 이후 콘솔/알림에서 노이즈로
# 안 잡힌다.

# ---------- 규칙 1: 명시적으로 억제 표시된 리소스는 평가 즉시 억제 ----------
# 원래는 Environment=dev로 매칭했는데, Environment 태그가 provider
# default_tags(00-versions.tf)로 이 계정 거의 모든 리소스에 자동으로 붙어서
# HIGH 심각도 finding(예: EC2 퍼블릭 IP)까지 같이 묻히는 문제가 있었다(라이브로
# 확인함 - 32건 중 상당수가 무관한 리소스 타입). Environment 태그는 "이 계정이
# dev인지"를 나타내는 용도로 그대로 두고, "이 리소스는 봐도 되고 안 봐도
# 된다(억제해도 된다)"는 별도 의사표시는 Environment=suppresstag로 분리한다 -
# 이 값을 가진 리소스는 지금 하나도 없으므로, 명시적으로 리소스에
# tags = { Environment = "suppresstag" }를 얹어서(provider default_tags를
# 리소스 레벨에서 오버라이드) 개별적으로 옵트인해야만 억제 대상이 된다.
resource "aws_securityhub_automation_rule" "suppress_dev_tagged" {
  rule_name   = "${local.name_prefix}-suppress-dev-tagged"
  description = "Environment=suppresstag 태그가 명시적으로 붙은 리소스의 finding만 평가 즉시 억제"
  rule_order  = 1
  rule_status = "ENABLED"
  is_terminal = false

  criteria {
    resource_tags {
      comparison = "EQUALS"
      key        = "Environment"
      value      = "suppresstag"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  actions {
    type = "FINDING_FIELDS_UPDATE"
    finding_fields_update {
      workflow {
        status = "SUPPRESSED"
      }
      note {
        text       = "Environment=suppresstag 태그(명시적 억제 옵트인) - Automation Rule에 의해 자동 억제됨"
        updated_by = "automation-rule-suppress-dev-tagged"
      }
    }
  }
}

# ---------- 규칙 2: 이미 위험 수용 결정된 항목은 재발해도 자동 억제 ----------
# scripts/security-hub-suppress-accepted-risks.sh가 수동으로 이미 처리한 것과
# 같은 title 목록 - 그 스크립트의 결정 이유를 그대로 재사용한다. 전체 목록이
# 아니라 반복적으로 재발하는(비용/아키텍처 트레이드오프성) 항목 위주로 추림 -
# 나머지는 새로 나올 때마다 사람이 한 번은 검토하는 게 안전하다고 판단.
resource "aws_securityhub_automation_rule" "suppress_known_accepted_risks" {
  rule_name   = "${local.name_prefix}-suppress-known-accepted-risks"
  description = "이미 위험 수용 결정된 유형의 finding은 재발해도 평가 즉시 억제 (근거: security-hub-suppress-accepted-risks.sh)"
  rule_order  = 2
  rule_status = "ENABLED"
  is_terminal = false

  criteria {
    title {
      comparison = "EQUALS"
      value      = "VPCs should be configured with an interface endpoint for Systems Manager"
    }
    title {
      comparison = "EQUALS"
      value      = "Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service"
    }
    title {
      comparison = "EQUALS"
      value      = "Amazon Inspector EC2 scanning should be enabled"
    }
    title {
      comparison = "EQUALS"
      value      = "GuardDuty Runtime Monitoring should be enabled"
    }
    title {
      comparison = "EQUALS"
      value      = "RDS DB instances should be configured with multiple Availability Zones"
    }
    title {
      comparison = "EQUALS"
      value      = "Secrets Manager secrets should have automatic rotation enabled"
    }
    title {
      comparison = "EQUALS"
      value      = "DynamoDB tables should automatically scale capacity with demand"
    }
    title {
      comparison = "EQUALS"
      value      = "CloudFormation stacks should have associated service roles"
    }
    workflow_status {
      comparison = "EQUALS"
      value      = "NEW"
    }
  }

  actions {
    type = "FINDING_FIELDS_UPDATE"
    finding_fields_update {
      workflow {
        status = "SUPPRESSED"
      }
      note {
        text       = "이미 위험 수용 결정됨(security-hub-suppress-accepted-risks.sh 근거 참고) - Automation Rule에 의해 재발 시 자동 억제"
        updated_by = "automation-rule-suppress-known-accepted-risks"
      }
    }
  }
}

# ---------- S3 최소 필수 관리형 규칙 (21번 파일에 없던 것만 추가) ----------
# S3 퍼블릭 오픈은 이 CSPM 파이프라인의 데모 시나리오 핵심 대상이라 반드시 필요.
# Conformance Pack(수십~수백 개 규칙 묶음, 평가 건수만큼 과금) 대신 이 2개만
# 개별 추가 - 이미 무료 티어(계정당 처음 몇 개 규칙 무료) 안에서 해결된다.
resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  name = "${local.name_prefix}-s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  name = "${local.name_prefix}-s3-bucket-public-write-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}
