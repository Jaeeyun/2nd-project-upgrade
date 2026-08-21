# =============================================================================
# ECR (도커 이미지 저장소)
# =============================================================================
# frontend / backend 이미지를 여기에 push하고, EKS 노드가 여기서 pull합니다.

resource "aws_ecr_repository" "frontend" {
  name = "${local.name_prefix}-frontend-repo"
  # [Security Hub ECR.2 관련 - 의도적으로 미조치] IMMUTABLE로 바꾸면 안전하지만,
  # build-and-push.sh가 매번 같은 태그(":latest")로 재push하는 방식이라 즉시
  # 깨진다(불변 태그는 같은 태그로 두 번 push 자체가 안 됨). 고치려면 태그
  # 전략을 git SHA/타임스탬프 기반으로 바꾸고 deploy.sh/k8s 매니페스트도 같이
  # 수정해야 하는 별도 작업이라 여기서는 보류. Track 4(기술부채) 참고.
  image_tag_mutability = "MUTABLE"
  force_delete         = true # 이미지가 남아있어도 terraform destroy로 리포지토리 삭제 가능

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "backend" {
  name                 = "${local.name_prefix}-backend-repo"
  image_tag_mutability = "MUTABLE" # ECR.2: 위 frontend와 동일한 이유로 보류
  force_delete         = true # 이미지가 남아있어도 terraform destroy로 리포지토리 삭제 가능

  image_scanning_configuration {
    scan_on_push = true
  }
}

# Security Hub ECR.3 대응 - 오래된/미사용 이미지 자동 정리
resource "aws_ecr_lifecycle_policy" "frontend" {
  repository = aws_ecr_repository.frontend.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "최근 10개 이미지만 유지"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "backend" {
  repository = aws_ecr_repository.backend.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "최근 10개 이미지만 유지"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 10
      }
      action = { type = "expire" }
    }]
  })
}
