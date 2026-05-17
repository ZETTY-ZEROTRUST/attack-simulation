"""
victim sub 풀 관리. 순차 enumeration / 랜덤 선택 모드 둘 다 지원.

env 변수
--------
VICTIM_SUB_START / VICTIM_SUB_END : 접근 가능한 사용자 id 범위 [START, END)
VICTIM_COUNT                      : 위 범위 안에서 실제로 공격할 사용자 수.
                                    비우면 범위 전체(END - START). 범위 초과 시 클램프.

세 시나리오(S4/S5/S5b)는 모두 각 사용자를 정확히 1회 방문한다.
한 계정을 여러 번 조회하는 분포가 필요하면 별도 시나리오로 추가할 것.
"""
import os
import random


def _range_bounds(start: int = None, end: int = None) -> tuple:
    start = start if start is not None else int(os.environ["VICTIM_SUB_START"])
    end = end if end is not None else int(os.environ["VICTIM_SUB_END"])
    return start, end


def _resolve_count(count: int, start: int, end: int) -> int:
    """공격할 사용자 수 결정. 미설정 → 범위 전체. 범위 초과 → 클램프."""
    span = end - start
    if count is None:
        raw = os.environ.get("VICTIM_COUNT", "").strip()
        count = int(raw) if raw else span
    return max(1, min(count, span))


def get_sequential_pool(start: int = None, end: int = None, count: int = None) -> list:
    """
    순차 enumeration용. S4 메인 시연 / S5(IP 분산 + sub 순차)에 사용.

    START부터 count명을 순차로 반환. list로 반환 — 호출처에서 [0]/[-1]
    인덱싱, len() 등이 자연스럽게 작동.
    """
    start, end = _range_bounds(start, end)
    n = _resolve_count(count, start, end)
    return list(range(start, start + n))


def get_shuffled_pool(start: int = None, end: int = None, count: int = None,
                      seed: int = 42) -> list:
    """
    랜덤 선택 enumeration용. S5b(IP 분산 + sub random) / S6(Slow & Low)에 사용.

    [START, END) 범위에서 count명을 비복원 추출(중복 없음)해 랜덤 순서로 반환.
    각 사용자가 최대 1회만 등장하므로 호출처는 그대로 순회하면 1인 1회 방문.

    seed=None  → 매 실행 다른 표본 (S5b).
    seed 고정  → 재현 가능한 표본 (S6, 기본 42).
    """
    start, end = _range_bounds(start, end)
    n = _resolve_count(count, start, end)
    rng = random.Random(seed)
    return rng.sample(range(start, end), n)
