#!/usr/bin/env bash
# =============================================================================
# 잔여 리소스 전체 스캔 스크립트
# =============================================================================
# terraform destroy가 "188 destroyed"라고 보고해도, 이 프로젝트에서 실제로
# 겪었던 것처럼(Secrets Manager 삭제 예약, Cost Anomaly Monitor 한도, WORM
# 버킷 Object Lock 등) AWS 쪽에 물리적으로 남는 리소스가 있을 수 있습니다.
# Terraform state가 아니라 AWS API에 직접 물어봐서 실제로 남아있는지 확인합니다.
#
# 사용법:
#   ./scripts/verify-cleanup.sh [name_prefix] [region]
#
# 예시:
#   ./scripts/verify-cleanup.sh demo-project-dev
#   ./scripts/verify-cleanup.sh demo-project-dev ap-northeast-2
set -uo pipefail

NAME_PREFIX="${1:-demo-project-dev}"
REGION="${2:-ap-northeast-2}"

echo "=========================================="
echo " '${NAME_PREFIX}' 관련 잔여 리소스 스캔 (리전: ${REGION})"
echo "=========================================="

section() { echo ""; echo "--- $1 ---"; }

section "1. Resource Groups Tagging API (가장 광범위한 1차 스캔)"
aws resourcegroupstaggingapi get-resources --region "$REGION" \
  --query "ResourceTagMappingList[?contains(ResourceARN, '${NAME_PREFIX}')].ResourceARN" \
  --output table 2>&1 || echo "  조회 실패(권한 확인 필요)"

section "2. IAM Roles (계정 전체, 리전 무관)"
aws iam list-roles \
  --query "Roles[?starts_with(RoleName, '${NAME_PREFIX}')].RoleName" \
  --output table 2>&1

section "3. IAM OIDC Provider (GitHub Actions용, 계정당 URL 1개 제한)"
aws iam list-open-id-connect-providers \
  --query "OpenIDConnectProviderList[].Arn" --output table 2>&1

section "4. IAM SAML Provider (Keycloak용)"
aws iam list-saml-providers \
  --query "SAMLProviderList[].Arn" --output table 2>&1

section "5. S3 버킷 (계정 전체)"
aws s3 ls 2>&1 | grep -i "$NAME_PREFIX" || echo "  없음 (정상)"

section "6. Cost Anomaly Monitor (반드시 us-east-1 - 글로벌 성격)"
aws ce get-anomaly-monitors --region us-east-1 \
  --query "AnomalyMonitors[?contains(MonitorName, '${NAME_PREFIX}')].[MonitorName,MonitorArn]" \
  --output table 2>&1

section "7. Security Lake (계정+리전당 1개 제한)"
aws securitylake list-data-lakes --region "$REGION" \
  --query "dataLakes[].dataLakeArn" --output table 2>&1 || echo "  없음 또는 조회 실패(활성화 안 됐으면 정상)"

section "8. CloudFormation 스택 (ASR 등)"
aws cloudformation list-stacks --region "$REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE ROLLBACK_COMPLETE CREATE_IN_PROGRESS DELETE_FAILED ROLLBACK_FAILED \
  --query "StackSummaries[?starts_with(StackName, '${NAME_PREFIX}')].[StackName,StackStatus]" \
  --output table 2>&1

section "9. VPC (demo VPC + Keycloak VPC 둘 다)"
aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=tag:Name,Values=${NAME_PREFIX}*" \
  --query "Vpcs[].[VpcId,Tags[?Key=='Name'].Value|[0]]" --output table 2>&1

section "10. EC2 인스턴스 (혹시 종료 안 된 것)"
aws ec2 describe-instances --region "$REGION" \
  --filters "Name=tag:Name,Values=${NAME_PREFIX}*" "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query "Reservations[].Instances[].[InstanceId,State.Name,Tags[?Key=='Name'].Value|[0]]" --output table 2>&1

section "11. RDS 인스턴스"
aws rds describe-db-instances --region "$REGION" \
  --query "DBInstances[?starts_with(DBInstanceIdentifier, '${NAME_PREFIX}')].[DBInstanceIdentifier,DBInstanceStatus]" \
  --output table 2>&1

section "12. EKS 클러스터"
aws eks list-clusters --region "$REGION" \
  --query "clusters[?starts_with(@, '${NAME_PREFIX}')]" --output table 2>&1

section "13. Secrets Manager (삭제 예약 상태 포함)"
aws secretsmanager list-secrets --region "$REGION" --include-planned-deletion \
  --query "SecretList[?starts_with(Name, '${NAME_PREFIX}')].[Name,DeletedDate]" --output table 2>&1

section "14. EventBridge Scheduler 스케줄"
aws scheduler list-schedules --region "$REGION" --name-prefix "$NAME_PREFIX" \
  --query "Schedules[].Name" --output table 2>&1

section "15. CloudWatch 로그 그룹"
aws logs describe-log-groups --region "$REGION" \
  --query "logGroups[?contains(logGroupName, '${NAME_PREFIX}')].logGroupName" \
  --output table 2>&1

section "16. NAT Gateway (가장 비싼 항목이라 특히 확인)"
aws ec2 describe-nat-gateways --region "$REGION" \
  --filter "Name=tag:Name,Values=${NAME_PREFIX}*" "Name=state,Values=pending,available" \
  --query "NatGateways[].[NatGatewayId,State]" --output table 2>&1

section "17. Amazon Managed Grafana Workspace"
aws grafana list-workspaces --region "$REGION" \
  --query "workspaces[?starts_with(name, '${NAME_PREFIX}')].[id,name]" --output table 2>&1

echo ""
echo "=========================================="
echo " 스캔 끝"
echo "=========================================="
echo "위 항목들 중 표(table)에 실제 값이 채워져 나온 게 있으면 아직 안 지워진 겁니다."
echo "'없음'/'None'/빈 테이블만 나왔으면 정상적으로 다 정리된 것입니다."
echo ""
echo "1번(Resource Groups Tagging API)이 제일 광범위해서, 거기 뭔가 걸리면"
echo "그 ARN을 보고 어떤 서비스인지 확인해서 해당 서비스의 delete 명령으로 지우세요."
