"""
JWT 디코드 헬퍼 (서명 검증 안 함, 시뮬용).

시뮬은 본인이 발급받았거나 본인이 위조한 토큰의 payload를 들여다보는 용도로만 사용.
운영 검증 경로에 들어가지 않으므로 서명 검증 생략한다.
"""
import json
import base64


def decode_payload(token: str) -> dict:
    """
    JWT payload(서명 검증 없음)를 dict로 반환.

    base64url padding을 자동 보정. exp/iat/sub/jti 등 모든 클레임에 접근 가능.
    """
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8")
    return json.loads(payload_json)
