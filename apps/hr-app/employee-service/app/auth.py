import json
import threading
import time

import jwt
import requests
import urllib3
from fastapi import Depends, HTTPException, Request
from jwt.algorithms import ECAlgorithm
from sqlalchemy.orm import Session

import config
import models
from database import get_db

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# X-Pomerium-Claim-Email은 평문 헤더라 클라이언트가 직접 위조해서 보낼 수 있으므로
# 신뢰의 근거로 쓰지 않는다. 대신 클라이언트가 위조할 수 없는 서명된
# x-pomerium-jwt-assertion을 Pomerium의 JWKS로 직접 검증한다.
# 배경: TROUBLESHOOTING.md의 "Pomerium / 헤더 스푸핑" 참고.
_jwks_keys: dict[str, object] = {}
_jwks_fetched_at = 0.0
_jwks_lock = threading.Lock()
_JWKS_TTL_SECONDS = 300


def _get_signing_key(kid: str):
    global _jwks_fetched_at
    now = time.time()
    with _jwks_lock:
        if not _jwks_keys or now - _jwks_fetched_at > _JWKS_TTL_SECONDS:
            # verify=False: Pomerium 인증서가 자체서명이고 이 IP는 우리 VPC 안에서만
            # 닿는 사설 경로라, Keycloak 쪽에 이미 적용한 것과 같은 근거로 완화함.
            resp = requests.get(config.POMERIUM_JWKS_URL, verify=False, timeout=5)
            resp.raise_for_status()
            keys = {}
            for jwk in resp.json().get("keys", []):
                keys[jwk["kid"]] = ECAlgorithm.from_jwk(json.dumps(jwk))
            _jwks_keys.clear()
            _jwks_keys.update(keys)
            _jwks_fetched_at = now
    return _jwks_keys.get(kid)


def get_current_email(request: Request) -> str:
    """Pomerium이 서명한 JWT(x-pomerium-jwt-assertion)를 검증해서 이메일을 뽑는다.
    평문 X-Pomerium-Claim-Email 헤더는 클라이언트가 위조할 수 있어 더 이상 쓰지 않는다.
    """
    assertion = request.headers.get("x-pomerium-jwt-assertion")
    if not assertion:
        raise HTTPException(
            status_code=401,
            detail="Pomerium 인증 정보가 없습니다. Pomerium을 통한 인증이 필요합니다.",
        )
    try:
        kid = jwt.get_unverified_header(assertion).get("kid")
        key = _get_signing_key(kid)
        if key is None:
            raise HTTPException(status_code=401, detail="서명 검증 키를 찾을 수 없습니다.")
        payload = jwt.decode(assertion, key=key, algorithms=["ES256"], options={"verify_aud": False})
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"JWT 검증 실패: {exc}") from exc
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="JWT에 email 클레임이 없습니다.")
    return email.strip().lower()


def get_current_employee(
    email: str = Depends(get_current_email), db: Session = Depends(get_db)
) -> models.Employee:
    """헤더의 이메일을 DB와 대조해서 실제 등록된 직원인지 확인한다.
    (헤더 값 자체를 그냥 신뢰하지 않고 반드시 DB 조회로 검증)
    """
    emp = db.query(models.Employee).filter(models.Employee.email == email).first()
    if not emp:
        raise HTTPException(
            status_code=404,
            detail=f"'{email}' 계정에 해당하는 직원 정보가 없습니다. 인사팀에 등록을 요청하세요.",
        )
    return emp
