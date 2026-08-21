# =============================================================================
# Output
# =============================================================================
# terraform apply 후 화면에 출력되는 값들. kubectl 설정이나 CI/CD에서 참조할 때 씁니다.

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "퍼블릭 서브넷 ID 목록"
  value       = aws_subnet.public[*].id
}

output "private_app_subnet_ids" {
  description = "프라이빗 앱 서브넷 ID 목록"
  value       = aws_subnet.private_app[*].id
}

output "eks_cluster_name" {
  description = "EKS 클러스터 이름 (aws eks update-kubeconfig 할 때 사용)"
  value       = aws_eks_cluster.main.name
}

output "eks_cluster_endpoint" {
  description = "EKS 컨트롤 플레인 엔드포인트"
  value       = aws_eks_cluster.main.endpoint
}

output "alb_controller_iam_role_arn" {
  description = "ALB Controller IRSA Role ARN (Helm 설치 시 serviceAccount 어노테이션에 사용)"
  value       = aws_iam_role.alb_controller.arn
}

output "rds_endpoint" {
  description = "RDS 연결 엔드포인트"
  value       = aws_db_instance.main.endpoint
}

output "ecr_frontend_repository_url" {
  description = "frontend ECR 리포지토리 URL"
  value       = aws_ecr_repository.frontend.repository_url
}

output "ecr_backend_repository_url" {
  description = "backend ECR 리포지토리 URL"
  value       = aws_ecr_repository.backend.repository_url
}

output "config_recorder_name" {
  description = "AWS Config 설정 레코더 이름"
  value       = aws_config_configuration_recorder.main.name
}

output "security_hub_account_id" {
  description = "Security Hub가 활성화된 계정 ID"
  value       = aws_securityhub_account.main.id
}

output "cost_anomaly_subscription_arn" {
  description = "Cost Anomaly Detection 구독 ARN"
  value       = aws_ce_anomaly_subscription.main.arn
}

output "name_prefix" {
  description = "리소스 이름 접두사 (검증 가이드에서 리소스 이름 조합할 때 사용)"
  value       = local.name_prefix
}

output "cloudtrail_name" {
  description = "CloudTrail 이름"
  value       = aws_cloudtrail.main.name
}

output "budget_name" {
  description = "AWS Budgets 예산 이름"
  value       = aws_budgets_budget.monthly_cost.name
}

output "keycloak_private_ip" {
  description = "Keycloak EC2 Private IP"
  value       = aws_instance.keycloak.private_ip
}