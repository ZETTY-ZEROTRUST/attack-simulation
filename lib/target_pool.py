"""
victim sub 풀 관리. enumeration / 랜덤화 모드 둘 다 지원.
"""
import os
import random


def get_sequential_pool(start: int = None, end: int = None) -> list:
    """
    순차 enumeration용. S4 메인 시연 / S5(IP 분산 + sub 순차)에 사용.

    list로 반환 — 호출처에서 [0]/[-1] 인덱싱, len() 등이 자연스럽게 작동.
    """
    start = start or int(os.environ["VICTIM_SUB_START"])
    end = end or int(os.environ["VICTIM_SUB_END"])
    return list(range(start, end))


def get_shuffled_pool(start: int = None, end: int = None, seed: int = 42) -> list:
    """랜덤화 enumeration. S6 Slow & Low에 사용 (순차 패턴 숨김)."""
    start = start or int(os.environ["VICTIM_SUB_START"])
    end = end or int(os.environ["VICTIM_SUB_END"])
    pool = list(range(start, end))
    rng = random.Random(seed)
    rng.shuffle(pool)
    return pool
