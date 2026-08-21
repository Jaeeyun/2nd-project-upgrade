from typing import List

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session

import models
import schemas
from auth import get_current_employee
from database import get_db

app = FastAPI(title="Employee Self-Service API")

# 참고: 테이블 생성/시드 데이터는 hr-service의 migrate.py(k8s Job)가 전담합니다.
# employee-service는 조회 전용이므로 여기서 create_all을 호출하지 않습니다.


@app.middleware("http")
async def no_store_cache(request, call_next):
    # 응답이 요청자(X-Pomerium-Claim-Email)별로 다른 개인정보라, 캐시 헤더가
    # 없으면 브라우저가 이전 로그인 사용자의 응답을 재사용할 수 있다 - 로그인한
    # 사람이 바뀌었는데 예전 사람 데이터가 그대로 보이는 문제로 실제로 나타났다.
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
@app.get("/api/employee/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/me", response_model=schemas.EmployeeInfoResponse)
@app.get("/api/employee/me", response_model=schemas.EmployeeInfoResponse)
def read_me(employee: models.Employee = Depends(get_current_employee)):
    """로그인한 본인의 정보만 반환한다. URL에 다른 사람 ID를 넣어서 조회하는 경로 자체가 없다."""
    return employee


@app.get("/me/history", response_model=List[schemas.ChangeHistoryResponse])
@app.get("/api/employee/me/history", response_model=List[schemas.ChangeHistoryResponse])
def read_my_history(
    employee: models.Employee = Depends(get_current_employee),
    db: Session = Depends(get_db),
):
    """로그인한 본인의 인사 변경 이력만 반환한다."""
    return (
        db.query(models.ChangeHistory)
        .filter(models.ChangeHistory.employee_id == employee.id)
        .order_by(models.ChangeHistory.changed_at.desc())
        .all()
    )
