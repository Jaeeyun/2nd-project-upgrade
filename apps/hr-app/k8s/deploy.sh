#!/usr/bin/env bash
# =============================================================================
# project-c HR 앱 배포 스크립트
# =============================================================================
# terraform apply로 인프라(Keycloak/Pomerium/ALB/target group/EKS/RDS/ECR)가
# 이미 떠 있다는 전제 하에, 그 위에 HR 앱을 배포한다. Pomerium 프라이빗 IP나
# target group ARN처럼 destroy/apply할 때마다 바뀌는 값들은 매번 terraform
# output과 AWS CLI로 새로 조회해서 채워 넣는다(하드코딩하면 재현 안 됨).
#
# 사전 조건:
#   - cd ~/project-c && terraform apply 완료
#   - aws eks update-kubeconfig 로 kubeconfig 등록 완료
#   - helm install aws-load-balancer-controller ... 완료 (EXECUTION_GUIDE.md 참고)
#   - employee-service/hr-service/frontend 도커 이미지가 ECR에 push 완료
#     (build-and-push.sh 참고)
#
# 사용법:
#   cd ~/project-c/hr-app/k8s
#   ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

TF_DIR=~/project-c

echo "▶ terraform output / AWS CLI로 동적 값 조회 중..."
export AWS_REGION="ap-northeast-2"
export AWS_ACCOUNT_ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

export DB_HOST
DB_HOST=$(cd "$TF_DIR" && terraform output -raw rds_endpoint | cut -d: -f1)

export DB_PASSWORD
DB_PASSWORD=$(grep '^db_password' "$TF_DIR/terraform.tfvars" | sed -E 's/^db_password\s*=\s*"(.*)"$/\1/')

export POMERIUM_PRIVATE_IP
POMERIUM_PRIVATE_IP=$(cd "$TF_DIR" && terraform state show aws_instance.pomerium | grep -E '^\s*private_ip\s*=' | awk -F'"' '{print $2}')

export EMPLOYEE_TG_ARN
EMPLOYEE_TG_ARN=$(aws elbv2 describe-target-groups --names demo-project-dev-employee-svc-tg --region "$AWS_REGION" --query "TargetGroups[0].TargetGroupArn" --output text)
export HR_TG_ARN
HR_TG_ARN=$(aws elbv2 describe-target-groups --names demo-project-dev-hr-svc-tg --region "$AWS_REGION" --query "TargetGroups[0].TargetGroupArn" --output text)
export FRONTEND_TG_ARN
FRONTEND_TG_ARN=$(aws elbv2 describe-target-groups --names demo-project-dev-hr-frontend-tg --region "$AWS_REGION" --query "TargetGroups[0].TargetGroupArn" --output text)

echo "  AWS_ACCOUNT_ID=$AWS_ACCOUNT_ID"
echo "  DB_HOST=$DB_HOST"
echo "  POMERIUM_PRIVATE_IP=$POMERIUM_PRIVATE_IP"
echo "  EMPLOYEE_TG_ARN=$EMPLOYEE_TG_ARN"
echo "  HR_TG_ARN=$HR_TG_ARN"
echo "  FRONTEND_TG_ARN=$FRONTEND_TG_ARN"

render() {
  local template="$1"
  local out="${template%.yaml}.rendered.yaml"
  envsubst < "$template" > "$out"
  echo "$out"
}

echo "▶ ConfigMap/Secret 렌더링 후 적용"
kubectl apply -f "$(render 00-employee-backend-config.yaml)"
kubectl apply -f "$(render 00-hr-backend-config.yaml)"

echo "▶ Deployment/Service 렌더링 후 적용"
kubectl apply -f "$(render 10-employee-service.yaml)"
kubectl apply -f "$(render 20-hr-service.yaml)"
kubectl apply -f "$(render 15-frontend.yaml)"

echo "▶ TargetGroupBinding 렌더링 후 적용"
kubectl apply -f "$(render 25-target-group-bindings.yaml)"

echo "▶ DB 마이그레이션/시드 Job (기존 Job이 있으면 삭제 후 재실행 - Job은 수정 불가)"
kubectl delete job hr-db-migrate -n hr-backend --ignore-not-found
kubectl apply -f "$(render 40-migrate-job.yaml)"
kubectl wait --for=condition=complete job/hr-db-migrate -n hr-backend --timeout=120s

echo "▶ 롤아웃 대기"
kubectl rollout status deployment/employee-service -n employee-backend --timeout=120s
kubectl rollout status deployment/hr-service -n hr-backend --timeout=120s
kubectl rollout status deployment/frontend -n frontend --timeout=120s

POMERIUM_PUBLIC_IP=$(cd "$TF_DIR" && terraform output -raw pomerium_public_ip)
echo
echo "✅ 배포 완료."
echo "Windows hosts 파일(C:\\Windows\\System32\\drivers\\etc\\hosts)에 아래 두 줄을 넣으세요:"
echo "  $POMERIUM_PUBLIC_IP  employee.company.com"
echo "  $POMERIUM_PUBLIC_IP  hr.company.com"
echo "저장 후 관리자 cmd에서: ipconfig /flushdns"
