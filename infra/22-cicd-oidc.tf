# =============================================================================
# CI/CD OIDC (ADR-006 결정 2)
# =============================================================================
# GitHub Actions가 AWS를 호출할 때 정적 키 대신 OIDC로 단기 Role을 assume하게
# 한다. 신뢰 정책에 특정 저장소·브랜치 조건을 걸어, 다른 저장소/브랜치에서는
# 이 Role을 못 쓰게 한다.

variable "github_org" {
  description = "GitHub organization/user 이름 (예: my-org)"
  type        = string
}

variable "github_repo" {
  description = "이 인프라를 배포하는 GitHub 저장소 이름"
  type        = string
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  # GitHub Actions OIDC의 thumbprint(공식적으로 문서화된 값, 주기적으로 GitHub이
  # 갱신할 수 있어 apply 전 최신값 확인 권장)
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_ci_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # main 브랜치에서 트리거된 워크플로만 허용 - PR 브랜치 등에서는 assume 불가.
    #
    # GitHub Actions의 sub 클레임은 문서에 흔히 나오는 "repo:org/repo:ref:..."
    # 리터럴 형태가 아니라 "repo:org@<owner_id>/repo@<repo_id>:ref:..."처럼
    # org/repo 뒤에 숫자 ID가 "@"로 붙는 계정도 있다 - 리터럴만 믿고 조건을
    # 걸면 AssumeRoleWithWebIdentity가 "Not authorized"로 막히므로 뒤에
    # 와일드카드를 붙여 두 형태를 모두 허용한다.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_org}*/${var.github_repo}*:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_ci" {
  name = "${local.name_prefix}-github-ci-role"
  # (한글: ADR-006: GitHub Actions가 OIDC로 assume하는 CI 전용 Role. 정적 키 없음.)
  # IAM Role description도 SG description과 마찬가지로 특정 ASCII 범위만
  # 허용하므로(한글 불가), description은 영문으로 쓰고 설명은 주석으로 남긴다.
  description        = "ADR-006: CI-only role assumed via OIDC by GitHub Actions. No static keys."
  assume_role_policy = data.aws_iam_policy_document.github_ci_trust.json
}

# CI가 실제로 필요한 최소 권한만. terraform apply를 CI가 하는 경우를 가정해
# 이 프로젝트가 관리하는 리소스 타입으로 한정한다(계정 전체 admin 아님).
# 실제 운용 시 이 목록은 점점 좁혀가는 게 맞음(ADR-007 CIEM 사이클 적용 대상).
data "aws_iam_policy_document" "github_ci_permissions" {
  statement {
    effect  = "Allow"
    actions = [
      "ec2:Describe*",
      "eks:Describe*",
      "eks:List*",
      "eks:UpdateAddon",
      "rds:Describe*",
      "ssm:SendCommand",
      "ssm:GetCommandInvocation",
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "iam:PassRole",
    ]
    resources = ["*"] # 초기 베이스라인 - ADR-007 결정 1(4주 관찰 후 최소화) 대상
  }

  statement {
    effect  = "Allow"
    actions = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:document/*"]
  }
}

resource "aws_iam_role_policy" "github_ci_permissions" {
  name   = "github-ci-baseline"
  role   = aws_iam_role.github_ci.id
  policy = data.aws_iam_policy_document.github_ci_permissions.json
}

output "github_ci_role_arn" {
  description = "GitHub Actions 워크플로 YAML의 role-to-assume 값으로 사용"
  value       = aws_iam_role.github_ci.arn
}
