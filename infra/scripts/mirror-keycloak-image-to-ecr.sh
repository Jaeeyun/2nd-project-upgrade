#!/usr/bin/env bash
# =============================================================================
# Keycloak 컨테이너 이미지를 quay.io에서 계정 소유 ECR로 1회 미러링
# =============================================================================
# Keycloak EC2가 프라이빗 서브넷(15-keycloak-vpc-peering.tf)에 있어서
# 인터넷으로 나가는 경로가 전혀 없다 - 그래서 quay.io에서 직접 pull이
# 불가능하고, 배포 전에 이 스크립트로 이미지를 미리 ECR에 올려둬야 한다.
#
# 언제 실행: terraform apply(특히 aws_instance.keycloak 최초 생성/재생성)
# 전에, 인터넷이 되는 본인 컴퓨터에서 1회. ECR 리포지토리는 Terraform이
# 먼저 만들어야 하므로(aws_ecr_repository.keycloak_mirror), 순서는:
#   1. terraform apply -target=aws_ecr_repository.keycloak_mirror
#   2. 이 스크립트 실행
#   3. terraform apply (나머지 전체)
#
# 필요 조건: 로컬에 Docker, 이 계정에 push 권한이 있는 AWS 자격증명.
set -euo pipefail

KEYCLOAK_VERSION="${KEYCLOAK_VERSION:-26.7.0}"
SOURCE_IMAGE="quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}"

cd "$(dirname "$0")/.."
ECR_REPOSITORY_URL=$(terraform output -raw keycloak_ecr_repository_url)
REGISTRY="${ECR_REPOSITORY_URL%%/*}"
# ECR 호스트명(<account>.dkr.ecr.<region>.amazonaws.com)에서 리전을 그대로
# 뽑아 쓴다 - 별도 output/변수 없이도 항상 실제 리포지토리와 일치함이 보장됨.
REGION=$(echo "$REGISTRY" | cut -d. -f4)

echo "▶ ${SOURCE_IMAGE} pull 중..."
docker pull --platform linux/amd64 "$SOURCE_IMAGE"

echo "▶ ${ECR_REPOSITORY_URL}:${KEYCLOAK_VERSION}로 태깅"
docker tag "$SOURCE_IMAGE" "${ECR_REPOSITORY_URL}:${KEYCLOAK_VERSION}"

echo "▶ ECR 로그인"
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"

echo "▶ push 중..."
docker push "${ECR_REPOSITORY_URL}:${KEYCLOAK_VERSION}"

echo ""
echo "완료. scan_on_push=true라 push 직후 자동으로 취약점 스캔이 시작됩니다."
echo "결과 확인: aws ecr describe-image-scan-findings --repository-name $(basename "$ECR_REPOSITORY_URL") --image-id imageTag=${KEYCLOAK_VERSION}"
echo ""
echo "MIRROR_DONE - ${ECR_REPOSITORY_URL}:${KEYCLOAK_VERSION}"
