# =============================================================================
# GuardDuty Foundational (ADR-003)
# =============================================================================
# ADR-003 결정 2/3: Foundational 탐지(CloudTrail 이상탐지, 알려진 악성 IP,
# S3/Malware Protection 등)는 켜고, Runtime Monitoring(EKS/EC2 컨테이너 런타임
# 에이전트)은 켜지 않는다 - 그 영역은 Falco가 담당하기로 결정했기 때문에,
# GuardDuty와 이중으로 띄우면 리소스 낭비 + 비용 중복이 생긴다.

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true # ADR-005 결정: S3 Protection 켬
    }
    kubernetes {
      audit_logs {
        enable = true # EKS Protection(Audit Log 감시) - Runtime Monitoring과는 별개 기능
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true # Malware Protection - 디스크 파일 시그니처 탐지, Falco와 안 겹침
        }
      }
    }
  }

  tags = {
    Name = "${local.name_prefix}-guardduty"
  }
}

# EKS/EC2 Runtime Monitoring은 의도적으로 활성화하지 않음(ADR-003 결정 3).
# aws_guardduty_detector_feature로 "EKS_RUNTIME_MONITORING"/"RUNTIME_MONITORING"을
# 켜는 리소스를 여기 추가하지 않는 것 자체가 그 결정을 코드로 표현한 것.

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}
