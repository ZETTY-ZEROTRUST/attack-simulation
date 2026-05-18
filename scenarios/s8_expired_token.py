"""
S8 — 비정상 장수명 토큰 (서명키 탈취 후 만료 회피).

행위:
- 단일 IP에서 forge_token 으로 토큰을 위조하되, TTL 을 정상(600s) 대신
  비정상적으로 길게(기본 7200s = 2h) 발급한다.
- 키를 탈취한 공격자는 매번 재위조하는 churn 을 줄이려 "오래 사는" 토큰을 만든다.
- /api/addresses/{sub} 조회.

S4 와의 차이:
    S4 — 정상 TTL(600s) 토큰으로 다수 sub enumeration(폭) → ip_user_diversity
    S8 — 토큰 자체가 비정상(장수명)         → token_violation
    즉 신호가 "폭"이 아니라 "토큰 규격 위반". 폭 신호를 피하려 victim 수는 작게.

기대 탐지 (UBA):
- token_violation — T007(exp-iat > 3600)=80 / T002(exp-iat > 1800)=70.
  결정론 팩터라 단독으로 total 80 → 알람. attacker_level = L2.
- --token-ttl 을 음수로 주면 이미 만료된 토큰 → T001(exp < now)=80.

탐지 측 무변경: token_violation.py 의 룰 T001~T007 이 이미 구현돼 있어, 본 시나리오는
공격 트래픽만 흘리면 event_aggregator → factor_engine 이 그대로 채점한다.
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
from lib.result_writer import ResultWriter

load_dotenv(_ROOT / ".env")

NORMAL_TTL = 600   # backend application-prod.yml 정상 토큰 TTL. 이보다 길면 규격 위반 후보.


def _expected_rule(token_ttl: int) -> str:
    if token_ttl < 0:
        return "T001(만료 exp<now)=80"
    if token_ttl > 3600:
        return "T007(장수명 exp-iat>3600)=80"
    if token_ttl > 1800:
        return "T002(장수명 exp-iat>1800)=70"
    return "미발동 (정상 TTL 범위)"


def run_s8(count: int = 8, token_ttl: int = 7200, interval: float = 1.0):
    """
    Parameters
    ----------
    count     : 공격할 victim sub 수 (VICTIM_SUB_START 부터). ip_user_diversity 같은
                폭 신호를 피해 token_violation 을 깨끗한 dominant 로 두려 작게(기본 8).
    token_ttl : 위조 토큰 TTL(초). 기본 7200(2h, 장수명) → T007.
                음수 → 이미 만료된 토큰 → T001. 1800~3600 → T002.
    interval  : 요청 간 sleep(초).
    """
    session = get_session()
    pool = get_sequential_pool()[:count]
    src_ip = os.environ.get("S8_SOURCE_IP")

    writer = ResultWriter("S8")
    kind = ("만료" if token_ttl < 0
            else "장수명" if token_ttl > NORMAL_TTL else "정상범위")
    print(f"[S8] 시작 — victim {len(pool)}명, 위조 토큰 TTL={token_ttl}s "
          f"({kind} / 정상 {NORMAL_TTL}s)")
    print(f"[S8] X-Forwarded-For: {src_ip or '(미위조)'}")

    try:
        for victim_id in pool:
            # ★ ttl_seconds 를 비정상값으로 — forge_token 이 그대로 exp 에 반영
            token = forge_token(victim_id, ttl_seconds=token_ttl)
            path = f"/api/addresses/{victim_id}"
            try:
                resp = call_api(session, path, token, src_ip=src_ip)
                writer.record(victim_id, src_ip, "GET", path, resp,
                              token_ttl=token_ttl)
            except Exception as e:
                writer.record_error(victim_id, src_ip, path, e,
                                    token_ttl=token_ttl)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n[S8] 사용자 중단")
    finally:
        writer.close()

    print(f"[S8] 종료 — {writer.total}건 (TTL {token_ttl}s 위조 토큰)")
    print(f"[S8] 기대 탐지: token_violation {_expected_rule(token_ttl)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=8,
                        help="공격할 victim sub 수 (기본 8 — 폭 신호 회피)")
    parser.add_argument("--token-ttl", type=int, default=7200,
                        help="위조 토큰 TTL(초). 기본 7200(장수명). 음수=만료, 1800~3600=T002")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="요청 간 sleep(초)")
    args = parser.parse_args()
    run_s8(args.count, args.token_ttl, args.interval)
