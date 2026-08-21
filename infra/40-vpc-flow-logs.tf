# =============================================================================
# VPC Flow Logs (Security Hub EC2.6 대응)
# =============================================================================
# Security Lake의 VPC_FLOW 소스(19-security-lake.tf)는 자체 관리형 수집
# 경로를 쓰기 때문에, EC2.6이 검사하는 "고전적인 VPC Flow Logs(aws_flow_log)"
# 활성화 여부와는 별개다 - 그래서 Security Lake를 켜놨어도 이 통제는 계속
# 실패로 남아있었다. main/keycloak 두 VPC 모두에 CloudWatch Logs로 향하는
# Flow Log를 추가로 켠다(트래픽량에 비례한 저비용, Security Lake와 중복
# 수집이지만 이 통제 자체가 요구하는 게 이 리소스임).

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc-flow-logs/${local.name_prefix}"
  retention_in_days = 30
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "vpc-flow-logs-to-cwl"
  role = aws_iam_role.vpc_flow_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "main_vpc" {
  vpc_id                   = aws_vpc.main.id
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn              = aws_iam_role.vpc_flow_logs.arn
  traffic_type              = "ALL"
}

resource "aws_flow_log" "keycloak_vpc" {
  vpc_id                   = aws_vpc.keycloak.id
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn              = aws_iam_role.vpc_flow_logs.arn
  traffic_type              = "ALL"
}

# 계정 기본 VPC(03-security.tf의 data.aws_vpc.default) - EC2.6이 "3/3"으로
# 실패 표시된 이유가 이 VPC까지 포함해서였음
resource "aws_flow_log" "account_default_vpc" {
  vpc_id                   = data.aws_vpc.default.id
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn              = aws_iam_role.vpc_flow_logs.arn
  traffic_type              = "ALL"
}
