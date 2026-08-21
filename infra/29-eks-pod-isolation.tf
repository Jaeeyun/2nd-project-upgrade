# =============================================================================
# EKS 파드 격리 자동조치 (100-SCENARIOS.md 35번, ADR-013/014 확장)
# =============================================================================
# Falco/GuardDuty가 EKS 안에서 이상 행위를 탐지했을 때, 사람이 Security Hub
# Custom Action을 눌러서 이 Lambda를 수동으로 트리거한다(자동 실행 아님 -
# ADR-005 결정 5, 파괴적이지는 않지만 서비스 영향이 있을 수 있는 조치라 사람
# 승인을 거침).

resource "aws_securityhub_action_target" "isolate_eks_pod" {
  # (한글: EKS 파드 격리 - 선택한 finding의 파드를 격리(quarantine 라벨 + deny-all NetworkPolicy))
  # SG/IAM Role description에서 겪은 것과 동일하게, Security Hub Custom Action의
  # name/description도 ASCII 범위를 벗어나면 거부될 수 있어 영문으로 통일.
  name        = "Isolate EKS Pod"
  identifier  = "IsolateEksPod"
  description = "Isolate the selected finding's pod (quarantine label + deny-all NetworkPolicy)"
}

data "archive_file" "eks_pod_isolate" {
  type        = "zip"
  source_file = "${path.module}/scripts/eks-pod-isolate.py"
  output_path = "${path.module}/.build/eks-pod-isolate.zip"
}

resource "aws_iam_role" "eks_pod_isolate" {
  name = "${local.name_prefix}-eks-pod-isolate-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_pod_isolate_basic_logs" {
  role       = aws_iam_role.eks_pod_isolate.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "eks_pod_isolate_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["eks:DescribeCluster"]
    resources = [aws_eks_cluster.main.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]
  }
}

resource "aws_iam_role_policy" "eks_pod_isolate_permissions" {
  name   = "eks-pod-isolate-permissions"
  role   = aws_iam_role.eks_pod_isolate.id
  policy = data.aws_iam_policy_document.eks_pod_isolate_permissions.json
}

resource "aws_iam_role_policy_attachment" "eks_pod_isolate_vpc" {
  role       = aws_iam_role.eks_pod_isolate.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# EKS 클러스터의 public endpoint는 eks_public_access_cidrs(관리자 IP 하나)로만
# 열려있으므로, 이 Lambda는 VPC(private_app)에 붙어 private endpoint로
# K8s API를 호출한다(session-revoke Lambda와 동일한 패턴).
resource "aws_security_group" "eks_pod_isolate_lambda" {
  name        = "${local.name_prefix}-eks-pod-isolate-lambda-sg"
  description = "eks-pod-isolate Lambda - outbound to EKS API(443) only"
  vpc_id      = aws_vpc.main.id
}

resource "aws_vpc_security_group_egress_rule" "eks_pod_isolate_lambda_to_eks" {
  security_group_id            = aws_security_group.eks_pod_isolate_lambda.id
  referenced_security_group_id = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

# 핸들러가 K8s API를 부르기 전에 eks:DescribeCluster(AWS API, NAT 경유)를
# 먼저 호출하므로, 클러스터 SG로만 나가는 위 규칙과 별개로 AWS API용
# 0.0.0.0/0:443도 필요하다.
resource "aws_vpc_security_group_egress_rule" "eks_pod_isolate_lambda_to_internet" {
  security_group_id = aws_security_group.eks_pod_isolate_lambda.id
  cidr_ipv4          = "0.0.0.0/0"
  from_port          = 443
  to_port             = 443
  ip_protocol        = "tcp"
  description        = "AWS API calls (eks:DescribeCluster) via NAT gateway"
}

resource "aws_vpc_security_group_ingress_rule" "eks_cluster_sg_from_pod_isolate_lambda" {
  security_group_id            = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  referenced_security_group_id = aws_security_group.eks_pod_isolate_lambda.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
}

resource "aws_lambda_function" "eks_pod_isolate" {
  function_name    = "${local.name_prefix}-eks-pod-isolate"
  role             = aws_iam_role.eks_pod_isolate.arn
  handler          = "eks-pod-isolate.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.eks_pod_isolate.output_path
  source_code_hash = data.archive_file.eks_pod_isolate.output_base64sha256

  vpc_config {
    subnet_ids         = aws_subnet.private_app[*].id
    security_group_ids = [aws_security_group.eks_pod_isolate_lambda.id]
  }

  environment {
    variables = {
      CLUSTER_NAME  = aws_eks_cluster.main.name
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
    }
  }
}

# ---------- 이 Lambda의 IAM Role을 K8s 안에서 인증 가능하게 등록 ----------
# kubernetes_groups로 명시적 그룹을 매핑해야 한다 - 이걸 안 주면 access
# entry가 만드는 K8s username이 IAM Role ARN이 아니라 EKS가 내부적으로
# 부여하는 assumed-role 세션 기반 이름이 되어, User 기준으로 바인딩하면
# 매칭이 안 돼 API 호출이 전부 403이 된다(34-k8s-namespaces-rbac.tf의
# dev-general 등과 동일한 패턴 - 아래 ClusterRoleBinding도 Group 기준).
resource "aws_eks_access_entry" "pod_isolate_lambda" {
  cluster_name      = aws_eks_cluster.main.name
  principal_arn     = aws_iam_role.eks_pod_isolate.arn
  type              = "STANDARD"
  kubernetes_groups = ["pod-isolator"]
}

# ---------- 이 Lambda에게 파드 라벨링/NetworkPolicy 생성 권한만(RBAC) ----------
resource "kubernetes_cluster_role" "pod_isolator" {
  metadata {
    name = "pod-isolator"
  }

  rule {
    api_groups = [""]
    resources  = ["pods"]
    verbs      = ["get", "patch"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies"]
    verbs      = ["get", "create", "patch"]
  }
}

resource "kubernetes_cluster_role_binding" "pod_isolator" {
  metadata {
    name = "pod-isolator-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.pod_isolator.metadata[0].name
  }

  subject {
    kind      = "Group"
    name      = "pod-isolator" # 위 access entry의 kubernetes_groups와 일치
    api_group = "rbac.authorization.k8s.io"
  }

  depends_on = [aws_eks_access_entry.pod_isolate_lambda]
}

# ---------- Security Hub Custom Action → EventBridge → 이 Lambda ----------
resource "aws_cloudwatch_event_rule" "isolate_eks_pod_action" {
  name = "${local.name_prefix}-isolate-eks-pod-action"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Custom Action"]
    resources   = [aws_securityhub_action_target.isolate_eks_pod.arn]
  })
}

resource "aws_cloudwatch_event_target" "isolate_eks_pod_lambda" {
  rule = aws_cloudwatch_event_rule.isolate_eks_pod_action.name
  arn  = aws_lambda_function.eks_pod_isolate.arn
}

resource "aws_lambda_permission" "allow_eventbridge_isolate" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.eks_pod_isolate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.isolate_eks_pod_action.arn
}
