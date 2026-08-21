from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class EmployeeCreateRequest(BaseModel):
    email: str
    name: str
    department: str
    position: str
    salary: int
    is_hr: bool = False


class EmployeeInfoResponse(BaseModel):
    id: int
    email: str
    name: str
    department: str
    position: str
    salary: int
    is_hr: bool

    class Config:
        from_attributes = True


class EmployeeSalaryResponse(BaseModel):
    id: int
    name: str
    department: str
    salary: int

    class Config:
        from_attributes = True


class PositionUpdateRequest(BaseModel):
    new_position: str
    reason: Optional[str] = None


class SalaryUpdateRequest(BaseModel):
    new_salary: int
    reason: Optional[str] = None


class ChangeHistoryResponse(BaseModel):
    id: int
    employee_id: int
    field_name: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None
    changed_by: str
    department: str
    reason: Optional[str] = None
    changed_at: datetime

    class Config:
        from_attributes = True
