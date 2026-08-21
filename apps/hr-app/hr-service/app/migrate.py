"""RDS에 테이블을 생성하고 초기 데이터를 넣는 1회성 스크립트.
k8s Job으로 실행: python migrate.py
(운영에서는 alembic 등의 정식 마이그레이션 도구로 교체 권장)
"""
from sqlalchemy import text

from database import Base, engine, SessionLocal
import models  # noqa: F401

# 기존에 이미 employees/change_history 테이블이 있는 상태에서 실행해도 안전하도록
# ALTER TABLE ... ADD COLUMN IF NOT EXISTS 로 신규 컬럼을 먼저 보강한다.
ALTER_STATEMENTS = [
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS email VARCHAR",
    "ALTER TABLE employees ADD COLUMN IF NOT EXISTS is_hr BOOLEAN NOT NULL DEFAULT FALSE",
    "ALTER TABLE change_history ADD COLUMN IF NOT EXISTS reason VARCHAR",
    "CREATE UNIQUE INDEX IF NOT EXISTS ix_employees_email ON employees (email)",
]

# 김철수/이영희/홍길동은 일반 직원, 박민수는 인사팀(is_hr=True)으로 지정.
# 인사팀 사이트(hr.company.com) 테스트는 박민수 계정으로 로그인해야 접근 가능.
SEED_EMPLOYEES = [
    {
        "email": "chulsoo.kim@company.com",
        "name": "김철수",
        "department": "개발팀",
        "position": "대리",
        "salary": 52000000,
        "is_hr": False,
    },
    {
        "email": "younghee.lee@company.com",
        "name": "이영희",
        "department": "영업팀",
        "position": "과장",
        "salary": 61000000,
        "is_hr": False,
    },
    {
        "email": "gildong.hong@company.com",
        "name": "홍길동",
        "department": "기획팀",
        "position": "사원",
        "salary": 45000000,
        "is_hr": False,
    },
    {
        "email": "minsu.park@company.com",
        "name": "박민수",
        "department": "인사팀",
        "position": "인사팀장",
        "salary": 70000000,
        "is_hr": True,
    },
]

if __name__ == "__main__":
    print("Creating tables if not exist...")
    Base.metadata.create_all(bind=engine)

    print("Applying schema patches (ALTER TABLE) for existing tables...")
    with engine.begin() as conn:
        for stmt in ALTER_STATEMENTS:
            print(f"  - {stmt}")
            conn.execute(text(stmt))

    db = SessionLocal()
    try:
        for data in SEED_EMPLOYEES:
            exists = (
                db.query(models.Employee)
                .filter(models.Employee.email == data["email"])
                .first()
            )
            if not exists:
                db.add(models.Employee(**data))
                print(f"  + seeded {data['email']} ({data['name']})")
            else:
                print(f"  = skip (already exists) {data['email']}")
        db.commit()
    finally:
        db.close()

    print("Done.")
