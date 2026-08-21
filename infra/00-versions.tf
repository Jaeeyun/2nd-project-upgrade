# =============================================================================
# Terraform 및 Provider 설정
# =============================================================================
# 이 파일은 "어떤 버전의 Terraform/AWS Provider를 쓸지"만 정의합니다.
# 실제 리소스는 다른 파일들에 있습니다.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4" # data "http"의 insecure = true(자체서명 인증서 스킵)가 이 버전부터 지원됨
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    helm = {
      # 현재 이 provider를 쓰는 리소스는 없음(Pod 보안 강제는
      # 34-k8s-namespaces-rbac.tf의 Pod Security Admission이 담당).
      # AWS Load Balancer Controller는 별도로 수동 helm install한다
      # (EXECUTION_GUIDE.md 참고) - 필요 없어지면 이 블록과 아래
      # provider "helm" 블록을 함께 제거해도 됨.
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.25"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4" # CIEM Lambda 패키징용 (24-ciem-lambda.tf)
    }
  }

  # -----------------------------------------------------------------------
  # (선택) 원격 state 저장 - 팀으로 작업하거나 이 컴퓨터가 아닌 곳에서도
  # terraform을 실행할 계획이 있다면 아래 주석을 풀고 S3 버킷을 미리
  # 만들어서 채워 넣으세요. 지금은 로컬(terraform.tfstate 파일)에 저장됩니다.
  #
  # backend "s3" {
  #   bucket = "demo-project-terraform-state"   # 미리 생성해둔 버킷 이름
  #   key    = "hr-system/terraform.tfstate"
  #   region = "ap-northeast-2"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
    }
  }
}

# IAM은 글로벌 서비스라 AttachRolePolicy 같은 관리 이벤트가 CloudTrail을 거쳐
# EventBridge 기본 버스로 전달될 때 그 리전이 항상 us-east-1이다(실측으로
# 확인 - ap-northeast-2에 규칙을 만들면 AWS/Events Invocations 지표가 0으로
# 전혀 매칭되지 않음). 44-iam-boundary-violation-watch.tf가 이 alias로
# EventBridge 규칙과 감시 Lambda를 us-east-1에 배포한다(Lambda 코드 안에서
# boto3 클라이언트는 명시적으로 ap-northeast-2를 지정해서 로그그룹/Secret은
# 그대로 기존 리전에 남긴다).
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
    }
  }
}

# EKS 클러스터에 K8s 리소스(네임스페이스, RBAC, NetworkPolicy)를 배포하기
# 위한 프로바이더. 클러스터가 먼저 있어야 하므로 04-eks.tf의 출력값을 참조한다.
provider "kubernetes" {
  host                   = aws_eks_cluster.main.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.main.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.main.name, "--region", var.aws_region]
  }
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.main.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.main.certificate_authority[0].data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.main.name, "--region", var.aws_region]
    }
  }
}

# 현재 AWS 계정 정보 (S3 버킷 이름 등에 계정 ID를 넣을 때 사용)
data "aws_caller_identity" "current" {}

# 사용 가능한 가용영역(AZ) 목록 조회
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  azs         = slice(data.aws_availability_zones.available.names, 0, 2)
}
