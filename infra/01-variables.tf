# =============================================================================
# 변수 정의
# =============================================================================
# 여기 정의된 변수들의 실제 값은 terraform.tfvars 파일에서 채웁니다.
# (terraform.tfvars는 .gitignore에 추가해서 Git에 올라가지 않게 하세요 — 특히 DB 비밀번호)

variable "aws_region" {
  description = "리소스를 배포할 AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "project_name" {
  description = "리소스 이름/태그에 쓰이는 프로젝트 이름"
  type        = string
  default     = "demo-project"
}

variable "environment" {
  description = "환경 이름 (dev, prod 등)"
  type        = string
  default     = "dev"
}

# ---------- 네트워크(VPC) ----------

variable "vpc_cidr" {
  description = "VPC CIDR 대역"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "퍼블릭 서브넷 CIDR (ALB, NAT Gateway가 위치)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_app_subnet_cidrs" {
  description = "프라이빗 애플리케이션 서브넷 CIDR (EKS 노드가 위치)"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "private_db_subnet_cidrs" {
  description = "프라이빗 DB 서브넷 CIDR (RDS가 위치)"
  type        = list(string)
  default     = ["10.0.100.0/24", "10.0.110.0/24"]
}

variable "single_nat_gateway" {
  description = "true면 NAT Gateway 1개만 사용(비용 절감), false면 AZ마다 1개씩"
  type        = bool
  default     = true
}

# ---------- EKS ----------

variable "eks_cluster_version" {
  description = "EKS(쿠버네티스) 버전. AWS가 표준 지원이 끝난 버전을 자동으로 업그레이드하므로, 이 값이 실제 클러스터 버전보다 낮으면 apply가 거부된다(InvalidParameterException: not eligible for rollback) - apply 전 aws eks describe-cluster로 실제 버전을 확인하고 이 값을 맞출 것."
  type        = string
  default     = "1.31"
}

variable "eks_node_instance_type" {
  description = "EKS 워커 노드 EC2 인스턴스 타입. t3.micro는 ENI 기반 파드 개수 제한이 약 4개라 서비스가 조금만 늘어도 'Too many pods'로 스케줄링이 실패하므로 t3.small 이상을 쓴다."
  type        = string
  default     = "t3.small"
}

variable "eks_node_desired_size" {
  description = "EKS 노드그룹 기본 노드 수"
  type        = number
  default     = 2
}

variable "eks_node_min_size" {
  description = "EKS 노드그룹 최소 노드 수"
  type        = number
  default     = 1
}

variable "eks_node_max_size" {
  description = "EKS 노드그룹 최대 노드 수"
  type        = number
  default     = 4
}

variable "eks_public_access_cidrs" {
  description = "EKS 컨트롤 플레인 API에 인터넷에서 접근을 허용할 CIDR 목록. 기본은 전체 허용(0.0.0.0/0)이며, 특정 IP로 좁히고 싶으면 이 값을 terraform.tfvars에서 덮어쓰세요 (예: [\"1.2.3.4/32\"]). 이 파일엔 IP를 직접 넣지 않습니다."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ---------- RDS ----------

variable "db_instance_class" {
  description = "RDS 인스턴스 클래스"
  type        = string
  default     = "db.t3.micro"
}

variable "multi_az_rds" {
  description = "true면 Multi-AZ(고가용성), false면 Single-AZ(비용 절감)"
  type        = bool
  default     = false
}

variable "db_name" {
  description = "RDS에 생성할 기본 데이터베이스 이름"
  type        = string
  default     = "demodb"
}

variable "db_username" {
  description = "RDS 관리자 계정 이름"
  type        = string
  default     = "adminuser"
}

variable "db_password" {
  description = "RDS 관리자 계정 비밀번호 (반드시 terraform.tfvars에서 채우고, 이 파일엔 값을 넣지 마세요)"
  type        = string
  sensitive   = true
}

# ---------- 계정 보안 베이스라인 (ADR-004) ----------

variable "alert_email" {
  description = "예산 초과(Budgets) 및 비용 이상 징후(Cost Anomaly Detection) 알림을 받을 이메일 주소. 반드시 terraform.tfvars에서 채우세요."
  type        = string
}

variable "monthly_budget_amount" {
  description = "월 예산 알림 기준 금액(USD). 80% 도달 시 alert_email로 알림이 갑니다."
  type        = string
  default     = "100"
}

variable "security_contact_name" {
  description = "AWS 계정 보안 연락처(Alternate Contact - SECURITY)에 등록할 이름. 반드시 terraform.tfvars에서 채우세요."
  type        = string
}

variable "security_contact_phone" {
  description = "AWS 계정 보안 연락처에 등록할 전화번호. 반드시 terraform.tfvars에서 채우세요."
  type        = string
}

variable "enable_cis_benchmark" {
  description = "true면 Security Hub에서 CIS AWS Foundations Benchmark 표준도 함께 활성화합니다. ADR-004 결정에 따라 기본값은 false이며(FSBP가 기본 베이스라인), 감사 대응 등으로 CIS 번호 체계 증적이 별도로 필요할 때만 true로 켜세요."
  type        = bool
  default     = false
}

# ---------- Keycloak (ADR-001/002 PoC, public subnet 통합) ----------

variable "keycloak_admin_cidr" {
  description = "Keycloak(퍼블릭 서브넷, 443) 접근을 허용할 CIDR. 이 값은 terraform apply를 실행하는 머신의 공인 IP도 포함해야 합니다 - apply 중 Keycloak 부트스트랩 완료를 이 머신이 직접 HTTPS로 확인하기 때문입니다(아래 11-keycloak.tf의 null_resource.wait_for_keycloak 참고). 이 endpoint는 Grafana SAML 로그인 페이지이기도 해서, 다른 IP의 사용자도 로그인해야 한다면 그 IP를 이 목록에 추가하거나(또는 임시로 0.0.0.0/0) 넣어야 합니다."
  type        = list(string)
}

variable "keycloak_instance_type" {
  description = "Keycloak EC2 인스턴스 타입"
  type        = string
  default     = "t3.medium"
}

variable "keycloak_realm_name" {
  description = "Keycloak에 만들 AWS 연동용 Realm 이름"
  type        = string
  default     = "corp"
}

variable "keycloak_test_users_password" {
  description = "테스트용 계정 8개(test-dev-general/test-dev-lead/test-dev-hr-backend/test-db-general/test-db-lead/test-ops-general/test-ops-lead/test-security-auditor) 공용 최초 비밀번호(로그인 시 강제 변경됨). terraform.tfvars에서 채우세요."
  type        = string
  sensitive   = true
}

variable "security_auditor_allowed_cidrs" {
  description = "security-auditor Role을 assume할 수 있는 CIDR 목록 (05-trust-policy-saml-security-auditor.json 반영)"
  type        = list(string)
}

# ---------- Keycloak VPC + Peering ----------
# Keycloak을 demo VPC와 분리된 별도 VPC에 두고 VPC Peering으로 연결한다. 이는
# "나중에 Keycloak을 사설망(Site-to-Site VPN)에 두고 그 경로로 demo VPC 자원과
# 통신하게 바꾼다"는 최종 목표를 저비용으로 미리 검증하기 위한 PoC 구조다.
# VPN Gateway(시간당 과금)를 실제로 띄우는 대신, 같은 리전 안에서 사설 IP로만
# 서로 도달 가능한 두 VPC 관계를 Peering으로 흉내낸다.
variable "keycloak_vpc_cidr" {
  description = "Keycloak을 둘 별도 VPC의 CIDR (demo VPC와 겹치지 않아야 함)"
  type        = string
  default     = "10.1.0.0/16"
}

variable "keycloak_vpc_public_subnet_cidr" {
  description = "Keycloak VPC 안의 퍼블릭 서브넷 CIDR (ALB 전용, EC2는 더 이상 여기 없음)"
  type        = string
  default     = "10.1.1.0/24"
}

# GitHub 포트폴리오 공개를 계기로 재검토 - Keycloak EC2를 여기로 옮긴다
# (11-keycloak.tf 상단 주석 및 14-keycloak-vpc-endpoints.tf 참고).
variable "keycloak_vpc_private_subnet_cidr" {
  description = "Keycloak VPC 안의 프라이빗 서브넷 CIDR (Keycloak EC2 전용)"
  type        = string
  default     = "10.1.2.0/24"
}

# ---------- ADR-008: 장기 로그 보관 (RDS 감사로그 적용분) ----------
variable "rds_audit_worm_retention_days" {
  description = "RDS 감사로그 S3 Object Lock(Compliance mode) 보존 기간(일). ISMS-P 요구사항에 따라 1~2년(365~730일) 권장. 이 기간 동안은 계정 소유자를 포함해 누구도 삭제/수정 불가."
  type        = number
  default     = 365
}
