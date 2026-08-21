from sqlalchemy import Boolean, Column, DateTime, Integer, String, func
from database import Base

# 참고: 이 테이블들은 hr-service와 동일한 RDS 스키마를 공유합니다.
# 실제 값 변경(직급/급여 수정)은 hr-service에서만 수행되고,
# employee-service는 조회(SELECT) 권한만 가진 DB 계정을 사용하는 것을 권장합니다.


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    department = Column(String, nullable=False, index=True)
    position = Column(String, nullable=False)
    salary = Column(Integer, nullable=False)
    is_hr = Column(Boolean, nullable=False, default=False)  # 인사팀 소속 여부


class ChangeHistory(Base):
    __tablename__ = "change_history"

    id = Column(Integer, primary_key=True, index=True)
    employee_id = Column(Integer, nullable=False, index=True)
    field_name = Column(String, nullable=False)  # "position" 또는 "salary"
    old_value = Column(String)
    new_value = Column(String)
    changed_by = Column(String, nullable=False)  # 변경을 수행한 인사팀 계정 이메일
    department = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=True)  # 변경 사유 (감사 로그)
    changed_at = Column(DateTime(timezone=True), server_default=func.now())
