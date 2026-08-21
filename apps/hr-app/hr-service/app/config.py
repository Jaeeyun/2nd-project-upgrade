import os

# ---------- RDS (PostgreSQL) ----------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "hrdb")
DB_USER = os.getenv("DB_USER", "hr_app")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

# X-Pomerium-Claim-Email은 평문 헤더라 클라이언트가 위조할 수 있어 신뢰하지 않는다.
# 대신 위조 불가능한 서명된 x-pomerium-jwt-assertion을 JWKS로 검증한다(auth.py).
POMERIUM_JWKS_URL = os.getenv("POMERIUM_JWKS_URL", "")
