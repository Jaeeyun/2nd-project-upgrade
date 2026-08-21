# =============================================================================
# CIS AWS Foundations Benchmark - CloudTrail 기반 메트릭 필터 + 알람 세트
# =============================================================================
# CloudWatch.1/4/5/6/7/8/9/10/11/12/13/14 대응(1차 반영 때 8/9를 빠뜨려서 이번에
# 추가). 전부 08-cloudtrail.tf가 만드는 CloudTrail→CloudWatch Logs 연동
# (aws_cloudwatch_log_group.cloudtrail)을 전제로 한다 - CloudTrail.5(로그
# 그룹 연동)를 먼저 켠 이유가 이것. 패턴은 AWS/CIS가 공식 문서에서 제공하는
# 표준 필터 그대로 사용.

locals {
  cis_cloudwatch_alarms = {
    root_account_usage = {
      control_id   = "CloudWatch.1"
      metric_name  = "RootAccountUsageCount"
      pattern      = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      alarm_desc   = "루트 계정 사용 감지"
    }
    iam_policy_changes = {
      control_id  = "CloudWatch.4"
      metric_name = "IAMPolicyChangesCount"
      pattern      = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
      alarm_desc  = "IAM 정책 변경 감지"
    }
    cloudtrail_config_changes = {
      control_id  = "CloudWatch.5"
      metric_name = "CloudTrailChangesCount"
      pattern      = "{($.eventName=CreateTrail)||($.eventName=UpdateTrail)||($.eventName=DeleteTrail)||($.eventName=StartLogging)||($.eventName=StopLogging)}"
      alarm_desc  = "CloudTrail 설정 변경 감지"
    }
    console_auth_failures = {
      control_id  = "CloudWatch.6"
      metric_name = "ConsoleAuthFailureCount"
      pattern      = "{($.eventName=ConsoleLogin) && ($.errorMessage=\"Failed authentication\")}"
      alarm_desc  = "AWS 콘솔 로그인 실패 감지"
    }
    s3_bucket_policy_changes = {
      control_id  = "CloudWatch.8"
      metric_name = "S3BucketPolicyChangesCount"
      pattern      = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}"
      alarm_desc  = "S3 버킷 정책 변경 감지"
    }
    config_changes = {
      control_id  = "CloudWatch.9"
      metric_name = "ConfigChangesCount"
      pattern      = "{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}"
      alarm_desc  = "AWS Config 설정 변경 감지"
    }
    cmk_deletion = {
      control_id  = "CloudWatch.7"
      metric_name = "CMKDeletionCount"
      pattern      = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}"
      alarm_desc  = "KMS 고객관리형 키 비활성화/삭제 예약 감지"
    }
    security_group_changes = {
      control_id  = "CloudWatch.10"
      metric_name = "SecurityGroupChangesCount"
      pattern      = "{($.eventName=AuthorizeSecurityGroupIngress)||($.eventName=AuthorizeSecurityGroupEgress)||($.eventName=RevokeSecurityGroupIngress)||($.eventName=RevokeSecurityGroupEgress)||($.eventName=CreateSecurityGroup)||($.eventName=DeleteSecurityGroup)}"
      alarm_desc  = "보안그룹 변경 감지"
    }
    nacl_changes = {
      control_id  = "CloudWatch.11"
      metric_name = "NaclChangesCount"
      pattern      = "{($.eventName=CreateNetworkAcl)||($.eventName=CreateNetworkAclEntry)||($.eventName=DeleteNetworkAcl)||($.eventName=DeleteNetworkAclEntry)||($.eventName=ReplaceNetworkAclEntry)||($.eventName=ReplaceNetworkAclAssociation)}"
      alarm_desc  = "네트워크 ACL 변경 감지"
    }
    network_gateway_changes = {
      control_id  = "CloudWatch.12"
      metric_name = "NetworkGatewayChangesCount"
      pattern      = "{($.eventName=CreateCustomerGateway)||($.eventName=DeleteCustomerGateway)||($.eventName=AttachInternetGateway)||($.eventName=CreateInternetGateway)||($.eventName=DeleteInternetGateway)||($.eventName=DetachInternetGateway)}"
      alarm_desc  = "네트워크 게이트웨이 변경 감지"
    }
    route_table_changes = {
      control_id  = "CloudWatch.13"
      metric_name = "RouteTableChangesCount"
      pattern      = "{($.eventName=CreateRoute)||($.eventName=CreateRouteTable)||($.eventName=ReplaceRoute)||($.eventName=ReplaceRouteTableAssociation)||($.eventName=DeleteRouteTable)||($.eventName=DeleteRoute)||($.eventName=DisassociateRouteTable)}"
      alarm_desc  = "라우팅 테이블 변경 감지"
    }
    vpc_changes = {
      control_id  = "CloudWatch.14"
      metric_name = "VpcChangesCount"
      pattern      = "{($.eventName=CreateVpc)||($.eventName=DeleteVpc)||($.eventName=ModifyVpcAttribute)||($.eventName=AcceptVpcPeeringConnection)||($.eventName=CreateVpcPeeringConnection)||($.eventName=DeleteVpcPeeringConnection)||($.eventName=RejectVpcPeeringConnection)||($.eventName=AttachClassicLinkVpc)||($.eventName=DetachClassicLinkVpc)||($.eventName=DisableVpcClassicLink)||($.eventName=EnableVpcClassicLink)}"
      alarm_desc  = "VPC 변경 감지"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each       = local.cis_cloudwatch_alarms
  name           = "${local.name_prefix}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.value.metric_name
    namespace = "CISBenchmark/${local.name_prefix}"
    value     = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.cis_cloudwatch_alarms

  alarm_name          = "${local.name_prefix}-${each.key}"
  alarm_description   = "${each.value.alarm_desc} (${each.value.control_id})"
  namespace           = "CISBenchmark/${local.name_prefix}"
  metric_name         = each.value.metric_name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.security_alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.cis]
}
