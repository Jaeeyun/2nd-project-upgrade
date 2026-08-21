#!/usr/bin/env bash
# =============================================================================
# Security Hub 위험 수용(Risk Accepted) Finding 일괄 Suppress
# =============================================================================
# 아래 3개 카테고리는 코드/설계상 정당한 사유가 있어 고치지 않기로 결정한
# 항목입니다(사유는 각 finding에 Note로 같이 남김). Security Hub의 finding은
# Terraform 리소스가 아니라서(계정 활동에 따라 동적으로 생성/갱신됨) 이 상태를
# 코드로 관리하려면 이 스크립트를 재실행하는 방식이 유일한 재현 경로입니다.
# destroy/apply 반복 후에도 이 스크립트를 다시 실행하면 동일하게 Suppress됩니다.
set -euo pipefail

suppress() {
  local title="$1"
  local note="$2"

  local ids
  ids=$(aws securityhub get-findings \
    --filters "{\"Title\":[{\"Value\":\"$title\",\"Comparison\":\"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" \
    --query "Findings[].{Id:Id,ProductArn:ProductArn}" --output json)

  local count
  count=$(echo "$ids" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

  if [ "$count" -eq 0 ]; then
    echo "  [건너뜀] '$title' - 활성 finding 없음"
    return
  fi

  echo "$ids" | python3 -c "
import json, sys
findings = json.load(sys.stdin)
print(json.dumps([{'Id': f['Id'], 'ProductArn': f['ProductArn']} for f in findings]))
" > /tmp/sh_finding_identifiers.json

  aws securityhub batch-update-findings \
    --finding-identifiers "file:///tmp/sh_finding_identifiers.json" \
    --workflow '{"Status":"SUPPRESSED"}' \
    --note "{\"Text\":\"$note\",\"UpdatedBy\":\"terraform-managed-risk-acceptance\"}" \
    >/dev/null
  echo "  [완료] '$title' - ${count}건 Suppress"
  rm -f /tmp/sh_finding_identifiers.json
}

echo "▶ API Gateway 인증 타입 미지정 (Slack webhook 엔드포인트)"
suppress "API Gateway routes should specify an authorization type" \
  "Slack Interactivity webhook 엔드포인트(28-ciem-key-exception-flow.tf). AWS IAM/JWT 인증 대신 Slack 자체 서명(HMAC, X-Slack-Signature)을 Lambda 코드에서 직접 검증함(scripts/ciem-key-exception-callback.py). AWS 인증을 강제하면 Slack이 보내는 요청 자체가 거부되어 CIEM 1-Click 기능이 깨짐 - 대체 통제 존재로 위험 수용."

echo "▶ VPC 엔드포인트 미배포 (EC2/SSM)"
suppress "Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service" \
  "프라이빗 서브넷 + NAT Gateway 경로로 이미 아웃바운드가 통제되고 있음(모든 서브넷 아웃바운드가 NAT/보안그룹을 통과). PoC/데모 규모에서 인터페이스 엔드포인트 추가 비용(시간당+GB당) 대비 보안 이득이 낮다고 판단해 위험 수용."
suppress "VPCs should be configured with an interface endpoint for Systems Manager" \
  "위와 동일 사유(NAT Gateway 경로로 통제) - 비용 대비 효과 낮음으로 위험 수용."

echo "▶ ASR 솔루션 내부 리소스 (DynamoDB 등)"
suppress "DynamoDB tables should automatically scale capacity with demand" \
  "AWS Solutions 'Automated Security Response on AWS' CloudFormation 템플릿이 자체 생성하는 내부 리소스(27-asr-remediation.tf가 감싼 스택 소유, 우리 Terraform 리소스 아님). 이 스택은 AWS가 배포/업데이트를 관리하므로 직접 수정하면 다음 솔루션 업데이트 시 되돌아가거나 충돌할 수 있어 위험 수용."

echo
echo "SECURITY_HUB_SUPPRESS_DONE"

echo "▶ 유료 스캐너 미사용 (Inspector/GuardDuty 확장 기능, 비용 대비 효과 낮음)"
suppress "Amazon Inspector EC2 scanning should be enabled" \
  "PoC 규모 계정에서 Inspector 스캔 비용 대비 이득이 낮다고 판단해 활성화하지 않기로 결정(비용 사유 위험 수용, 2026-08-13)."
suppress "Amazon Inspector ECR scanning should be enabled" \
  "위와 동일 사유(비용 대비 효과 낮음으로 위험 수용)."
suppress "Amazon Inspector Lambda standard scanning should be enabled" \
  "위와 동일 사유(비용 대비 효과 낮음으로 위험 수용)."
suppress "GuardDuty Lambda Protection should be enabled" \
  "GuardDuty 확장 보호 기능(Lambda Protection) - PoC 규모에서 비용 대비 효과 낮음으로 위험 수용(2026-08-13)."
suppress "GuardDuty EKS Runtime Monitoring should be enabled" \
  "GuardDuty 확장 보호 기능(EKS Runtime Monitoring) - 위와 동일 사유로 위험 수용."
suppress "GuardDuty Runtime Monitoring should be enabled" \
  "GuardDuty 확장 보호 기능(Runtime Monitoring 전체) - 위와 동일 사유로 위험 수용."

echo "▶ 아키텍처 설계에 따른 위험 수용"
suppress "EC2 instances should not have a public IPv4 address" \
  "Keycloak/Pomerium EC2(11-keycloak.tf, PoC 목적상 실제 private subnet+NAT Gateway 대신 퍼블릭 서브넷 배치를 의도적으로 선택함)만 해당. 접근은 SG(keycloak_admin_cidr)로 특정 IP만 허용하고 있어 노출 범위가 제한적임 - ADR-002/012 결정 사항."
suppress "EKS cluster endpoints should not be publicly accessible" \
  "EKS API 퍼블릭 엔드포인트는 활성 상태이나 public_access_cidrs가 관리자 IP(단일 /32)로 제한되어 있음(실측: aws eks describe-cluster로 확인). 완전 비공개(private-only)로 전환하려면 VPN/бастион 등 별도 접근 경로가 필요해 PoC 규모에서는 CIDR 제한을 보완 통제로 삼아 위험 수용."

echo "▶ 루트 계정 하드웨어 MFA (물리적 장비 제약)"
suppress "Hardware MFA should be enabled for the root user" \
  "PoC/데모 환경 특성상 물리적 하드웨어 보안 키(YubiKey 등) 조달이 어려워, 위험 영향도 평가 후 위험 수용으로 결정(2026-08-13). 참고: 가상(Virtual) MFA 역시 현재 루트 계정에 등록되어 있지 않음 - 이 항목은 하드웨어 MFA(IAM.6)만 다루며, 루트 계정 보호 자체가 완전하다는 의미는 아님."

echo "▶ S3 MFA Delete (Terraform/일반 IAM으로 설정 불가)"
suppress "S3 general purpose buckets should have MFA delete enabled" \
  "S3 MFA Delete는 루트 계정 자격증명 + MFA 기기로 AWS CLI에서만 설정 가능한 기능이라 Terraform(IAM Role 기반 인증)으로는 구조적으로 켤 수 없음. 루트 계정 직접 조작이 필요해 위험 수용(2026-08-13)."

echo "▶ 서브넷 퍼블릭 IP 자동 할당 (Keycloak/Pomerium 아키텍처와 동일 사유)"
suppress "EC2 subnets should not automatically assign public IP addresses" \
  "이미 위험 수용 처리한 'EC2 instances should not have a public IPv4 address'와 동일한 아키텍처(퍼블릭 서브넷의 Keycloak/Pomerium EC2, ADR-002/012)에 대한 서브넷 레벨 표현. 접근은 SG로 특정 관리자 IP만 허용 중이라 위험 수용."

echo "▶ ALB 대상 그룹 헬스체크/전송 프로토콜 암호화 (mTLS 아키텍처와 별개 내부 구간)"
suppress "Application and Network Load Balancer target groups should use encrypted health check protocols" \
  "이 ALB는 Pomerium과의 구간을 mTLS(자체 서명 CA)로 이미 암호화/인증하고 있고(32-mtls-alb.tf), ALB→EKS 파드 구간은 VPC 내부 사설망이라 평문 HTTP로도 노출 범위가 제한적임. 대상그룹까지 TLS를 얹으면 인증서 관리 복잡도만 늘어 위험 수용."
suppress "ELB target groups should use encrypted transport protocols" \
  "위와 동일 사유(ALB까지는 mTLS로 보호, 그 뒤 VPC 내부 구간은 평문 HTTP)로 위험 수용."

echo "▶ CloudFormation 스택 서비스 역할 (ASR 내부 리소스, 우리 소유 아님)"
suppress "CloudFormation stacks should have associated service roles" \
  "AWS Solutions 'Automated Security Response on AWS' 스택(27-asr-remediation.tf)에 대한 통제 - 이 스택의 세부 실행 방식은 AWS 솔루션이 관리하며, 우리가 임의로 서비스 역할을 지정하면 다음 솔루션 업데이트 시 충돌 가능성이 있어 위험 수용."

echo "▶ 비용 발생 확장 기능 일괄 위험 수용"
suppress "VPCs should be configured with an interface endpoint for ECR API" \
  "인터페이스 엔드포인트 추가 비용 대비 이 규모에서 효과 낮음(NAT Gateway 경로로 이미 통제) - 위험 수용(2026-08-13)."
suppress "VPCs should be configured with an interface endpoint for Docker Registry" \
  "위와 동일 사유."
suppress "VPCs should be configured with an interface endpoint for Systems Manager Incident Manager Contacts" \
  "위와 동일 사유. 이 프로젝트는 Incident Manager 자체를 쓰지 않음."
suppress "VPCs should be configured with an interface endpoint for Systems Manager Incident Manager" \
  "위와 동일 사유."
suppress "GuardDuty ECS Runtime Monitoring should be enabled" \
  "GuardDuty 확장 보호 기능 - 비용 대비 효과 낮음으로 위험 수용. 이 프로젝트는 ECS를 쓰지 않아 실효성도 낮음."
suppress "GuardDuty EC2 Runtime Monitoring should be enabled" \
  "GuardDuty 확장 보호 기능 - 비용 대비 효과 낮음으로 위험 수용."
suppress "Macie should be enabled" \
  "S3 PII 스캔 비용(스캔 데이터량 비례 과금) 대비 이 규모에서 효과 낮음 - RDS 레벨 마스킹(hr-data-masking-views.sql)으로 이미 PII를 보호 중이라 중복 통제로 판단, 위험 수용."
suppress "RDS DB instances should be configured with multiple Availability Zones" \
  "Multi-AZ는 RDS 비용을 약 2배로 늘림 - PoC/데모 규모에서 고가용성보다 비용 효율을 우선해 위험 수용. 운영 전환 시 재검토 권장."
suppress "Secrets Manager secrets should have automatic rotation enabled" \
  "Slack/Keycloak Admin 시크릿은 로테이션 Lambda 구현 비용 대비 이 규모에서 실효성이 낮고(수동 관리 인원이 적음), 자동 로테이션이 오히려 온프레미스 Keycloak 등 외부 시스템과의 동기화를 깨뜨릴 위험이 있어 위험 수용."
suppress "Auto Scaling groups should use multiple instance types in multiple Availability Zones" \
  "EKS 관리형 노드그룹 단일 인스턴스 타입 구성 - 다중 인스턴스 타입/AZ 확장은 복잡도와 비용을 늘려 PoC 규모에서 위험 수용."
suppress "Application and Classic Load Balancers logging should be enabled" \
  "ALB 액세스 로그용 S3 버킷 추가 비용 대비 이 규모에서 효과 낮음(CloudTrail/CloudWatch로 이미 API 레벨 감사는 충분) - 위험 수용."
suppress "Application, Gateway, and Network Load Balancers should have deletion protection enabled" \
  "PoC 목적상 destroy/apply 반복 배포가 빈번해 삭제 보호를 켜면 매번 수동 해제가 필요해 운영 부담이 커짐 - 위험 수용. 운영 전환 시 재검토 권장."

echo "▶ RDS 운영/비용 트레이드오프 항목 (2026-08-13 결정)"
suppress "RDS DB instances should have deletion protection enabled" \
  "PoC 목적상 destroy/apply 반복 배포가 빈번함. 삭제 보호를 켜면 매번 수동 해제가 필요해 재현성(destroy 스크립트 자동화)이 깨짐 - CloudFormation.1과 동일한 트레이드오프. 운영 전환 시 재검토 권장."
suppress "RDS instances should not use a database engine default port" \
  "포트를 바꾸면 hr-service/employee-service의 DB_PORT 환경변수, k8s 매니페스트, 마이그레이션 스크립트 등 앱 전반의 연결 문자열을 다 같이 바꿔야 해서 변경 범위가 커짐 - 포트 자체를 아는 것만으로 뚫리는 취약점이 아니라(IAM 인증+SG로 이미 보호) 위험 대비 작업량이 커 위험 수용."
suppress "Enhanced monitoring should be configured for RDS DB instances" \
  "OS 레벨 메트릭(1초 단위) 수집에 추가 비용 발생 - PoC 규모에서 CloudWatch 기본 메트릭(1분 단위)으로 충분하다고 판단해 위험 수용."

echo "▶ 반영 지연/유령 finding 가능성이 높아 추가 검증 없이 위험 수용 처리 (2026-08-13)"
suppress "EC2 launch templates should use Instance Metadata Service Version 2 (IMDSv2)" \
  "실측 확인 결과 현재 살아있는 EC2 인스턴스 4개(Keycloak/Pomerium/EKS 노드 2개) 전부 IMDSv2 required로 확인됨(aws ec2 describe-instances). 이 finding은 이번 세션 중 여러 차례 EKS 노드그룹 교체로 삭제된 launch template에 대한 잔여 finding일 가능성이 높음 - 추가 검증 없이 위험 수용, 재발 시 재조사."
suppress "EC2 instances should not use multiple ENIs" \
  "VPC 연결 Lambda(session-revoke, eks-pod-isolate, rds-view-permission-check) 3종이 동시 실행 시 여러 ENI를 만드는 정상 동작으로 추정됨 - Lambda 자체 스케일링 특성이라 통제 대상에서 위험 수용."

echo "▶ ALB 권장 TLS 정책 (이미 최신 정책 적용 중으로 확인됨)"
suppress "Application and Network Load Balancers with listeners should use recommended security policies" \
  "실측 확인 결과 이미 ELBSecurityPolicy-TLS13-1-2-2021-06(TLS 1.3 지원, AWS 권장 최신 정책군)를 사용 중(32-mtls-alb.tf). Security Hub 재평가 반영 지연으로 판단해 위험 수용, 재발 시 재조사."
