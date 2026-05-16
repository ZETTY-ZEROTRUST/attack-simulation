"""
S2 — JWT 토큰 하이재킹 (진짜 로그인 기반).

행위:
- 1단계: victim이 KT 가정 회선(VICTIM_SOURCE_IP)에서 /auth/login으로 정상 로그인 →
         auth-server가 ES256 + KMS 서명 진짜 토큰 발급. 5분간 정상 활동.
- 2단계: 공격자가 카페·공용망(ATTACKER_SOURCE_IP)에서 같은 토큰으로 민감 endpoint burst
         (탈취 시뮬: token 자체는 진짜, source IP만 다름).

핵심:
- forge_token 안 씀 — auth-server가 발급한 실제 토큰을 그대로 사용. jti/iat 등도 진짜.
- 같은 access token이 두 IP에서 관측되는 게 본질 — 서명/jti가 동일하므로 UBA는
  "같은 토큰의 회선 점프"로 인식 가능.
- IDOR 활용 없음 — victim 본인의 user_id에 대한 자원만 조회 (자기 데이터).

기대 탐지:
- F-TokenHijack: 동일 jti(또는 access token hash)가 5분 내 서로 다른 IP/ASN에서 관측 → raw 100
- 회선 점프 (KT residential → Public WiFi) → 가중치 1.5x
- 응답 민감도 High (/api/addresses) → F-Resp 70 결합 → final_score ≥ 90
"""
import os
import sys
import time
import random
import argparse
from pathlib import Path

import requests
from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from lib.http_client import get_session, call_api
from lib.token_utils import decode_payload

load_dotenv(_ROOT / ".env")


def login(session: requests.Session, base_url: str, email: str, password: str,
          src_ip: str = None, timeout: float = 5.0) -> str:
    """
    victim 회선(XFF)에서 /auth/login 호출. auth-server가 발급한 access token 반환.
    """
    url = f"{base_url.rstrip('/')}/auth/login"
    headers = {"Content-Type": "application/json"}
    if src_ip:
        headers["X-Forwarded-For"] = src_ip
    resp = session.post(
        url,
        headers=headers,
        json={"email": email, "password": password},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["accessToken"]


def run_s2(
    victim_phase_minutes: int = 5,
    attacker_burst: int = 8,
):
    """
    Parameters
    ----------
    victim_phase_minutes : 1단계 (정상 활동) 지속 시간 (분)
    attacker_burst : 2단계 burst 요청 수
    """
    session = get_session()

    base_url = os.environ["ZETI_ALB_URL"]
    victim_email = os.environ["VICTIM_EMAIL"]
    victim_password = os.environ["VICTIM_PASSWORD"]
    victim_ip = os.environ.get("VICTIM_SOURCE_IP", "222.110.15.50")
    attacker_ip = os.environ.get("ATTACKER_SOURCE_IP", "101.235.1.77")

    print(f"[S2] === 사전: victim 정상 로그인 (XFF={victim_ip}) ===")
    try:
        access_token = login(
            session, base_url, victim_email, victim_password, src_ip=victim_ip
        )
    except Exception as e:
        print(f"[S2] 로그인 실패: {e}")
        return

    payload = decode_payload(access_token)
    victim_id = int(payload["sub"])
    jti = payload.get("jti", "(no-jti)")
    ttl = payload.get("exp", 0) - payload.get("iat", 0)
    needed = victim_phase_minutes * 60 + 60  # phase + burst 여유 1분
    print(
        f"[S2] 토큰 발급 성공 — user_id={victim_id}, jti={jti[:8]}..., ttl={ttl}s"
    )
    if 0 < ttl < needed:
        print(
            f"[S2] ⚠️ 경고: 토큰 TTL({ttl}s) < 필요({needed}s) — "
            f"2단계 burst 진입 전 만료될 위험. victim-minutes 줄이거나 auth-server "
            f"jwt.expiration을 늘리세요."
        )

    print(
        f"[S2] === 1단계: Victim 정상 활동 "
        f"({victim_phase_minutes}분, X-Forwarded-For={victim_ip}) ==="
    )

    # 1단계 — victim source IP에서 정상 패턴 (자기 자원 조회)
    phase1_end = time.time() + victim_phase_minutes * 60
    phase1_count = 0
    try:
        while time.time() < phase1_end:
            path = random.choices(
                [
                    "/api/users/me",
                    f"/api/orders/{victim_id}",
                    f"/api/addresses/{victim_id}",
                ],
                weights=[7, 2, 1],
            )[0]
            try:
                resp = call_api(session, path, access_token, src_ip=victim_ip)
                phase1_count += 1
                if resp.status_code != 200:
                    print(
                        f"[S2-P1] non-200 status={resp.status_code} path={path}"
                    )
            except Exception as e:
                print(f"[S2-P1] error: {e}")
            time.sleep(random.uniform(15, 45))
    except KeyboardInterrupt:
        print(f"\n[S2] 사용자 중단 (1단계 중)")
        return

    print(f"[S2] 1단계 종료 — {phase1_count}건 정상 호출")
    print(
        f"[S2] === 2단계: 공격자 탈취 후 burst "
        f"({attacker_burst}건, X-Forwarded-For={attacker_ip}) ==="
    )

    # 2단계 — 같은 token, 다른 source IP에서 민감 정보 burst
    phase2_count = 0
    try:
        for i in range(attacker_burst):
            path = random.choice(
                [
                    f"/api/addresses/{victim_id}",
                    f"/api/orders/{victim_id}",
                    "/api/users/me",
                ]
            )
            try:
                resp = call_api(session, path, access_token, src_ip=attacker_ip)
                phase2_count += 1
                print(
                    f"[S2-P2] burst {i+1}/{attacker_burst}  "
                    f"path={path}  status={resp.status_code}"
                )
            except Exception as e:
                print(f"[S2-P2] error: {e}")
            time.sleep(random.uniform(2, 5))
    except KeyboardInterrupt:
        print(f"\n[S2] 사용자 중단 (2단계 중)")

    print(f"[S2] 종료 — 1단계 {phase1_count}건, 2단계 burst {phase2_count}건")
    print(
        f"[S2] 기대 탐지: 동일 jti({jti[:8]}...)가 두 IP "
        f"({victim_ip} → {attacker_ip})에서 관측 → F-TokenHijack 발동"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--victim-minutes", type=int, default=5)
    parser.add_argument("--burst", type=int, default=8)
    args = parser.parse_args()
    run_s2(args.victim_minutes, args.burst)
