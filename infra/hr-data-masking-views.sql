-- =============================================================================
-- HR RDS PII 마스킹 뷰 — 최종 실제 스키마(employees, change_history) 기준
-- (AWS 공식 "Dynamic data masking in Amazon RDS for PostgreSQL" 블로그의 뷰
-- 기반 패턴을 이 프로젝트 스키마에 맞게 적용한 버전)
-- https://aws.amazon.com/blogs/database/dynamic-data-masking-in-amazon-rds-for-postgresql-amazon-aurora-postgresql-and-babelfish-for-aurora-postgresql/
--
-- ---------- 두 개의 서로 다른 권한 축이 있다는 걸 먼저 이해하고 넘어가세요 ----------
-- 1) AWS IAM Role(general-user/approver/security-auditor, ADR-001) — "RDS에
--    접속할 수 있는가"를 결정. 인프라 레벨.
-- 2) employees.is_hr 플래그 — 애플리케이션 자체가 "화면에 급여를 보여줄지"를
--    판단하는 앱 레벨 권한. Pomerium 뒤에 있는 이 HR 앱이 로그인한 사용자의
--    이메일(Pomerium 헤더)로 employees.email을 조회해서 is_hr을 확인하는
--    방식으로 추정됩니다.
-- 이 두 축은 서로 대체 관계가 아닙니다. CloudShell로 psql을 직접 여는 경우
-- (ADR-004/16-rds-isolated-access.tf 경로)는 애플리케이션을 거치지 않으므로
-- is_hr 체크가 아예 실행되지 않습니다. 그래서 여기 마스킹 뷰가 여전히
-- 필요합니다 - "앱을 거치지 않고 DB에 직접 붙는" 경로를 위한 별도 방어선입니다.
--
-- 적용 방법:
--   1. terraform apply로 RDS가 뜬 뒤(06-rds.tf의 pgAudit 파라미터 변경으로
--      인스턴스가 한 번 재부팅됩니다), 마스터 계정으로 이 스크립트를 실행:
--      psql -h <rds_endpoint> -U <db_username> -d <db_name> -f hr-data-masking-views.sql
--   2. IAM DB 인증(06-rds.tf에서 이미 켬)으로 접속하는 IAM Role별 DB 사용자를
--      만들고, 아래에서 만든 "마스킹된 뷰"에만 권한을 줍니다. 원본 테이블에는
--      아무도 직접 SELECT 못 하게 막습니다(마스터 계정, 애플리케이션 계정 제외).
-- =============================================================================

-- ---------- 0. pgAudit 활성화 ----------
-- RDS for PostgreSQL은 오브젝트 감사용 역할 이름을 "rds_pgaudit"으로 고정해서만
-- 허용합니다(다른 이름 불가 - AWS 공식 문서).
CREATE ROLE rds_pgaudit NOLOGIN;
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- employees와 change_history 둘 다 감사 대상으로 지정. 이 GRANT 덕분에
-- pgaudit.log 세션 설정과 무관하게, 이 두 테이블을 건드리는 순간 무조건
-- 로그에 남습니다(오브젝트 레벨 감사).
GRANT SELECT, INSERT, UPDATE, DELETE ON employees TO rds_pgaudit;
GRANT SELECT, INSERT, UPDATE, DELETE ON change_history TO rds_pgaudit;

-- ---------- 1. IAM 인증으로 접속할 DB 역할 만들기 ----------
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'general_user_readonly') THEN
    CREATE ROLE general_user_readonly LOGIN;
    GRANT rds_iam TO general_user_readonly;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'approver_readonly') THEN
    CREATE ROLE approver_readonly LOGIN;
    GRANT rds_iam TO approver_readonly;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'security_auditor_readonly') THEN
    CREATE ROLE security_auditor_readonly LOGIN;
    GRANT rds_iam TO security_auditor_readonly;
  END IF;

  -- ADR-019: db-lead(AWS IAM Role)가 접속하는 DB 관리자 역할. 기존 3종은 뷰
  -- 조회만 가능한 순수 읽기전용이라, 스키마 변경(신규 컬럼 추가 시 마스킹 뷰
  -- 갱신 등, 100-SCENARIOS.md 69번 시나리오)을 처리할 권한 주체가 없었다.
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'db_admin') THEN
    CREATE ROLE db_admin LOGIN;
    GRANT rds_iam TO db_admin;
    -- 테이블 소유자(보통 마스터 계정)의 멤버로 편입시켜 DDL 권한 확보(아래 참고).
  END IF;

  -- 30-rds-permission-drift-check.tf의 Lambda가 매일 권한 드리프트를 점검/복구할 때
  -- 쓰는 역할. REVOKE를 실행해야 하므로 테이블 소유자 권한이 필요합니다.
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'remediation_admin') THEN
    CREATE ROLE remediation_admin LOGIN;
    GRANT rds_iam TO remediation_admin;
    -- 테이블 소유자(보통 마스터 계정)의 멤버로 편입시켜 REVOKE 권한 확보.
  END IF;
END
$$;

-- remediation_admin/db_admin이 employees/change_history의 실질 소유자 권한을
-- 가져야 하는 이유: (1) information_schema.role_table_grants는 그랜터/그랜티/
-- 멤버/소유자 관계로만 보이므로, 이 GRANT가 없으면 다른 계정이 부여한 드리프트
-- GRANT를 아예 못 보고 REVOKE 대상에서 누락시킨다(30-rds-permission-drift-check.tf
-- Lambda가 drift_count=0을 반환해도 실제로는 우회 권한이 살아있는 거짓음성이 됨),
-- (2) REVOKE 자체도 소유자 권한 없이는 실행할 수 없다. db_username 변수 기본값
-- (adminuser)과 항상 일치해야 하므로 플레이스홀더 대신 실제 값으로 고정합니다 -
-- db_username을 바꿔 배포한다면 이 줄도 같이 바꾸세요.
GRANT adminuser TO remediation_admin;
GRANT adminuser TO db_admin;

-- ---------- 2. 마스킹 뷰 스키마 분리 ----------
CREATE SCHEMA IF NOT EXISTS masked;

-- ---------- 3. employees 마스킹 뷰 ----------
-- salary만 가립니다. email/name/department/position/is_hr은 사내 조직도
-- 수준 정보로 보고 그대로 노출합니다 - email은 change_history.changed_by와
-- 매칭해서 "누가 바꿨는지" 추적할 때도 필요합니다.
CREATE OR REPLACE VIEW masked.employees_general AS
SELECT
  id,
  email,
  name,
  department,
  position,
  is_hr,
  NULL::integer AS salary  -- 급여는 아예 노출 안 함
FROM employees;

CREATE OR REPLACE VIEW masked.employees_audit AS
SELECT
  id,
  email,
  name,
  department,
  position,
  is_hr,
  salary  -- 감사관은 실제 급여 확인 가능(이상 급여 지급 여부 등 감사 목적)
FROM employees;

-- ---------- 4. change_history 마스킹 뷰 ----------
-- field_name이 'salary'인 행만 old_value/new_value를 가립니다. 'position'/
-- 'employee_created'는 애초에 민감하지 않으므로(또는 employee_created처럼
-- old_value/new_value가 원래 비어있는 경우도 있음) 그대로 보여줍니다.
-- changed_by(이메일)와 reason은 누가·왜 바꿨는지 추적하는 핵심 정보라 항상 노출합니다.
CREATE OR REPLACE VIEW masked.change_history_general AS
SELECT
  id,
  employee_id,
  field_name,
  CASE WHEN field_name = 'salary' THEN '****' ELSE old_value END AS old_value,
  CASE WHEN field_name = 'salary' THEN '****' ELSE new_value END AS new_value,
  changed_by,
  department,
  reason,
  changed_at
FROM change_history;

CREATE OR REPLACE VIEW masked.change_history_audit AS
SELECT
  id,
  employee_id,
  field_name,
  old_value,
  new_value,  -- 감사관은 급여 변경 전/후 실제 값까지 확인 가능
  changed_by,
  department,
  reason,
  changed_at
FROM change_history;

-- ---------- 5. 권한 부여: 원본 테이블은 잠그고, 뷰에만 권한 ----------
REVOKE ALL ON employees FROM PUBLIC;
REVOKE ALL ON change_history FROM PUBLIC;
REVOKE ALL ON employees, change_history FROM general_user_readonly, approver_readonly, security_auditor_readonly;

GRANT USAGE ON SCHEMA masked TO general_user_readonly, approver_readonly, security_auditor_readonly;

GRANT SELECT ON masked.employees_general, masked.change_history_general TO general_user_readonly, approver_readonly;
GRANT SELECT ON masked.employees_audit, masked.change_history_audit TO security_auditor_readonly;

-- ---------- 확인 ----------
-- 아래 커맨드로 실제 마스킹이 적용됐는지 확인하세요:
--   SET ROLE general_user_readonly;
--   SELECT * FROM masked.employees_general LIMIT 5;
--   SELECT * FROM masked.change_history_general WHERE field_name = 'salary' LIMIT 5;
--   RESET ROLE;
--
-- 급여 변경 이력만 따로 감사하고 싶을 때(감사관용):
--   SELECT employee_id, old_value, new_value, changed_by, reason, changed_at
--   FROM masked.change_history_audit
--   WHERE field_name = 'salary'
--   ORDER BY changed_at DESC;
--
-- is_hr=true인 사람이 최근에 만든 변경 이력만 보고 싶을 때(권한 오남용 점검용):
--   SELECT ch.* FROM masked.change_history_audit ch
--   JOIN masked.employees_audit e ON e.email = ch.changed_by
--   WHERE e.is_hr = true
--   ORDER BY ch.changed_at DESC;
