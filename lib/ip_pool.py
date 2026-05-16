"""
시뮬용 분산 IP 풀 (S5 전용).

XFF 위조 기반이므로 실제 ASN과 무관하게 임의 IP를 생성한다.
S5 풀은 "Mixed Hosting / VPS" 의도로 4종 prefix를 섞는다:

  prefix              할당 사유
  -----------------   --------------------------------------------
  203.0.113   (/24)   RFC 5737 TEST-NET-3 (시뮬용 placeholder)
  198.51.100  (/24)   RFC 5737 TEST-NET-2 (시뮬용 placeholder)
  192.0.2     (/24)   RFC 5737 TEST-NET-1 (시뮬용 placeholder)
  45.32       (/16)   Vultr Holdings — 실제 VPS 사업자

옥텟 분리 정책 (단일 IP 시나리오와 충돌 방지):
  단일 IP 시나리오 (S2/S4/S6): 마지막 옥텟 1~99
  S5 분산 풀                 : 마지막 옥텟 100~254 (기본값)
"""
import random

# 쿠팡 2024 사고 비율: 2,300 IP × 3,367 계정 ≈ 1.4억 건
# 즉 IP 풀 크기는 계정 풀의 약 0.683배.
# S5/S5b의 ip_pool_size 자동 계산에 사용.
COUPANG_IP_TO_ACCOUNT_RATIO = 2300 / 3367  # ≈ 0.683

ASN_CIDR_BLOCKS = {
    "documentation_a": "203.0.113",   # /24
    "documentation_b": "198.51.100",  # /24
    "documentation_c": "192.0.2",     # /24
    "vps_vultr":       "45.32",       # /16
}


def get_distributed_ips(
    count: int = 50,
    seed: int = 7,
    classes: list = None,
    min_octet: int = 100,
    max_octet: int = 254,
) -> list:
    """
    분산 IP 풀 생성.

    Parameters
    ----------
    count     : 풀 크기 (S5 기본 50~100)
    seed      : 재현 가능한 풀 생성용 시드
    classes   : 사용할 CIDR 키 목록 (기본 4종 전부)
    min_octet : 마지막 옥텟 최소값 (기본 100, 단일 IP 시나리오와 분리)
    max_octet : 마지막 옥텟 최대값 (기본 254)
    """
    rng = random.Random(seed)
    classes = classes or list(ASN_CIDR_BLOCKS.keys())

    ips = []
    for _ in range(count):
        klass = rng.choice(classes)
        prefix = ASN_CIDR_BLOCKS[klass]
        # /24(점 2개)면 마지막 옥텟만, /16(점 1개)면 두 옥텟 채움
        if prefix.count(".") == 1:
            ips.append(
                f"{prefix}.{rng.randint(0, 255)}.{rng.randint(min_octet, max_octet)}"
            )
        else:
            ips.append(f"{prefix}.{rng.randint(min_octet, max_octet)}")
    return ips
