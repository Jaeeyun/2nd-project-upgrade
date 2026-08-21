# =============================================================================
# HR 앱 NetworkPolicy (hr-backend 네임스페이스) — 기본 전면 차단 + 허용 규칙
# =============================================================================
# hr-backend 네임스페이스는 기본적으로 모든 인그레스를 막고, hr-service의
# 실제 포트(8000)에 대해서만 var.vpc_cidr 대역의 트래픽을 허용한다.
#
# ⚠️ 정직하게 밝혀둘 한계: "ALB에서 오는 트래픽만 허용"이 의도지만, EKS 파드도
# VPC CNI로 이 vpc_cidr 대역의 IP를 받기 때문에, 같은 클러스터의 다른 파드가
# hr-service에 직접 붙는 경로(mTLS ALB를 거치지 않는 경로)까지 완전히 차단하진
# 못한다. 더 정확히 좁히려면 ALB 전용 서브넷 분리나 서비스 메시가 필요하다.
#
# 이 NetworkPolicy가 실제로 데이터플레인에서 강제되려면 VPC CNI의 네트워크
# 정책 에이전트가 켜져 있어야 한다 - 04-eks.tf의 aws_eks_addon.vpc_cni
# (`enableNetworkPolicy=true`) 참고. 이게 꺼지면 이 오브젝트들은 K8s API엔
# 정상 존재해도 트래픽은 전혀 막지 않는다(TROUBLESHOOTING.md 참고).

resource "kubernetes_network_policy" "hr_app_default_deny" {
  metadata {
    name      = "default-deny-ingress"
    namespace = "hr-backend"
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress"]
  }
}

resource "kubernetes_network_policy" "hr_app_allow_from_alb" {
  metadata {
    name      = "allow-ingress-from-alb-only"
    namespace = "hr-backend"
  }

  spec {
    pod_selector {
      match_labels = {
        app = "hr-service"
      }
    }

    ingress {
      from {
        ip_block {
          cidr = var.vpc_cidr
        }
      }
      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }

    policy_types = ["Ingress"]
  }
}
