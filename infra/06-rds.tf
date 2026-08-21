# =============================================================================
# RDS (PostgreSQL)
# =============================================================================
# 프라이빗 DB 서브넷에만 위치하고, EKS 노드가 있는 VPC 내부에서만 접근 가능합니다
# (03-security.tf의 rds_sg 참고). 인터넷에서 직접 접근 불가능합니다.

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = aws_subnet.private_db[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet-group"
  }
}

resource "aws_db_parameter_group" "postgres_pg" {
  name   = "${local.name_prefix}-postgres-pg"
  family = "postgres15"

  parameter {
    name  = "log_min_duration_statement"
    value = "2000" # 2초 이상 걸리는 쿼리는 여전히 일반 운영 로그로 남김
  }

  # ---------- pgAudit: employees 테이블만 대상으로 하는 오브젝트 레벨 감사 ----------
  # log_statement=all(DB 전체 모든 쿼리)에서 pgAudit 오브젝트 감사로 전환. 이러면
  # employees 테이블을 건드리는 쿼리만 로그에 남고(볼륨/비용 급감), 그 외 테이블은
  # 안 남습니다. ADR-008 "실시간은 짧게, 장기 증적은 별도 저장소" 원칙과도 맞물려서
  # 최근 30일치만 CloudWatch에 두고(아래 log group), 그 이상은 17-rds-audit-worm.tf의
  # S3 Object Lock WORM 버킷으로 흘려보냅니다.
  #
  # 주의: pgaudit.log_parameter=off는 "바인딩된 파라미터
  # 값"만 숨깁니다. SQL 문에 리터럴로 직접 박힌 값(사람이 CloudShell에서
  # `WHERE resident_registration_no = '901231-...'`처럼 직접 타이핑하는 경우)은
  # 여전히 SQL 문 자체와 함께 로그에 남습니다. 그래서 아래 CloudWatch Data
  # Protection 마스킹을 반드시 같이 씁니다 - pgAudit는 "범위를 좁히는" 역할,
  # Data Protection은 "그래도 새는 걸 가리는" 역할로 이중 방어합니다.
  parameter {
    name         = "shared_preload_libraries"
    value        = "pgaudit"
    apply_method = "pending-reboot" # 정적 파라미터라 인스턴스 재부팅 후 적용됨
  }

  parameter {
    name         = "pgaudit.role"
    value        = "rds_pgaudit" # RDS PostgreSQL은 이 고정된 이름만 허용함(AWS 문서)
    apply_method = "pending-reboot"
  }

  # 세션 레벨 광범위 로깅은 꺼둠(pgaudit.role의 오브젝트 레벨 감사에만 의존) -
  # employees 테이블에 대한 GRANT는 hr-data-masking-views.sql에서 rds_pgaudit
  # 역할에 부여합니다.
  parameter {
    name  = "pgaudit.log"
    value = "none"
  }

  parameter {
    name  = "pgaudit.log_parameter"
    value = "0" # 바인딩 파라미터 값은 로그에 안 남김 (위 주의사항 참고)
  }

  # 접속/해제 시점도 남겨서 "누가 언제 붙었는지"를 재구성할 수 있게 함
  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }
}

# pgAudit이 걸러내지 못하는(리터럴 값 포함 SQL 문) 나머지 PII를 이차로 마스킹
# (CloudWatch Logs Data Protection - 스캔한 GB당 과금되는 유료 기능).
#
# 주의: salary(정수)는 AWS 관리형 PII 식별자 목록에 "이게 급여
# 숫자다"를 인식하는 패턴이 없어서, 이 정책이 salary 값 자체를 로그에서
# 가려주지는 못합니다. salary를 지키는 실질적인 방어선은 이 정책이 아니라
# pgAudit의 오브젝트 스코핑(employees/change_history만 감사 대상으로 좁힘)과
# log_parameter=off(바인딩 파라미터 미기록) 쪽입니다. 아래 정책은 email/name이
# 로그에 리터럴로 찍히는 경우를 잡아주는 역할입니다(실제 스키마에 email 컬럼이
# 있는 걸 확인해서 다시 추가함).
resource "aws_cloudwatch_log_data_protection_policy" "rds_postgresql_pii" {
  log_group_name = aws_cloudwatch_log_group.rds_postgresql.name

  # 실제 스키마(employees/change_history) 기준 email/name 컬럼이 있어서 이 둘만
  # 넣었습니다. 주소·전화번호·카드번호는 이 스키마에 없는 컬럼이라 스캔 비용만
  # 나가고 매칭될 일이 없어 뺐습니다. 컬럼이 추가되면 그때 식별자를 추가하세요.
  policy_document = jsonencode({
    Name        = "HRDataMaskingPolicy"
    Description = "RDS 쿼리 로그에 남는 직원 이메일/이름을 자동 마스킹"
    Version     = "2021-06-01"
    Statement = [

      {
        Sid = "audit"
        DataIdentifier = [
          "arn:aws:dataprotection::aws:data-identifier/Name",
          "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
        ]
        Operation = {
          Audit = {
            FindingsDestination = {}
          }
        }
      },
      {
        Sid = "redact"
        DataIdentifier = [
          "arn:aws:dataprotection::aws:data-identifier/Name",
          "arn:aws:dataprotection::aws:data-identifier/EmailAddress",
        ]
        Operation = {
          Deidentify = {
            MaskConfig = {}
          }
        }
      }
    ]
  })
}

# RDS 로그를 CloudWatch로 내보낼 로그 그룹. ADR-008 원칙(실시간/최근 조회는
# 짧게 CloudWatch에, 장기 증적은 별도 WORM 저장소로)에 따라 30일만 보관하고,
# 장기 보관은 17-rds-audit-worm.tf의 S3 Object Lock 버킷이 담당합니다.
resource "aws_cloudwatch_log_group" "rds_postgresql" {
  name              = "/aws/rds/instance/${local.name_prefix}-postgres-db/postgresql"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "rds_upgrade" {
  name              = "/aws/rds/instance/${local.name_prefix}-postgres-db/upgrade"
  retention_in_days = 7
}

resource "aws_db_instance" "main" {
  identifier     = "${local.name_prefix}-postgres-db"
  engine         = "postgres"
  engine_version = "15.13"
  instance_class = var.db_instance_class

  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password # terraform.tfvars에서 채움 - 이 파일엔 평문 값 없음

  parameter_group_name = aws_db_parameter_group.postgres_pg.name

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  multi_az = var.multi_az_rds

  backup_retention_period = 7 # Security Hub RDS.11 대응 - 자동 백업 활성화(무료, 인스턴스 저장용량 이내는 추가 과금 없음)
  backup_window            = "16:00-16:30" # UTC 기준 - 한국시간 새벽 1~1시반, 트래픽 적은 시간대
  copy_tags_to_snapshot    = true # Security Hub RDS.17 대응 - 무료

  # 기본값(false)이면 이 리소스의 변경사항이 다음 유지보수 시간까지 대기
  # 상태로만 큐잉되고 실제로는 반영되지 않는다 - 데모 환경은 변경이 바로
  # 반영돼야 검증 가능하므로 즉시 적용으로 강제.
  apply_immediately = true

  # IAM DB 인증 활성화: ADR-001/018에서 만든 IAM Role(dev-general/dev-lead/
  # ops-general/ops-lead/security-auditor) 신원으로 DB 접속 토큰을 발급받게 함.
  # 정적 db_password는 RDS 인스턴스를 처음 만들 때(마스터 계정)만 쓰고, 실제
  # 사람 접속은 IAM 인증으로 전환하는 걸 권장 (AWS Database Blog 공식 권고 -
  # 별도 SQL 스크립트로 DB 사용자/권한을 만들어야 완성됨, hr-data-masking-views.sql 참고)
  iam_database_authentication_enabled = true

  skip_final_snapshot = true # 데모/개발용. 운영 환경이라면 false로 바꾸고 스냅샷 남기세요.

  depends_on = [
    aws_cloudwatch_log_group.rds_postgresql,
    aws_cloudwatch_log_group.rds_upgrade,
  ]

  tags = {
    Name = "${local.name_prefix}-postgres-db"
  }
}
