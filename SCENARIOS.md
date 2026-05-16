# 시나리오별 행위 정리

각 시나리오의 victim/attacker 행위, 시간 추이, UBA 관점 관측, 기대 탐지 신호를 정리한 문서.
검토 후 코드 수정 지시 시 참고하는 단일 출처.

> 시나리오 한눈에 보기 표 / IP 색깔 매트릭스 / 실행 명령은 `README.md` 참조. 여기서는 행위 자체에만 집중.

---

## 목차

- [S2 — JWT 토큰 하이재킹](#s2--jwt-토큰-하이재킹)
- [S4 — 서명키 탈취 + 즉시 Enumeration](#s4--서명키-탈취--즉시-enumeration)
- [S5 — IP 분산 + sub 순차](#s5--ip-분산--sub-순차)
- [S5b — IP 분산 + sub random](#s5b--ip-분산--sub-random)
- [S6 — Slow & Low + Impossible Travel](#s6--slow--low--impossible-travel)

---

## S2 — JWT 토큰 하이재킹

파일: `scenarios/s2_token_hijack.py`

### 전체 타임라인

```
t=0 ────────── t=0~5min ────────── t=5min ────────── t=5min+α
 │                  │                   │                  │
 │  P0: 로그인       │  P1: 정상 활동    │  P2: 탈취 시점   │  P2: 공격 burst
 │  (1회)           │  (Victim)         │  (가상 사건)      │  (Attacker)
 │                  │                   │                  │
 └─ POST /auth/login └─ GET /api/* x N  └─ (코드상 즉시) ──── └─ GET /api/* x 8
    XFF=victim_ip      XFF=victim_ip                          XFF=attacker_ip
    → access_token     같은 token                             같은 token
```

P2의 "탈취 사건" 자체는 코드에 없음 — 같은 process가 IP만 바꿔서 호출하는 것으로 시뮬. 토큰이
메모리에 그대로 남아있는 상태에서 IP만 attacker로 바뀌는 게 핵심.

### P0 — 사전 로그인 (Victim, 1회)

| 항목 | 값 |
|---|---|
| 주체 | **Victim** |
| source IP (XFF) | `VICTIM_SOURCE_IP = 222.110.15.50` — KT 가정 회선 |
| HTTP | `POST {ZETI_ALB_URL}/auth/login` |
| Body | `{"email": "user001@zetty.test", "password": "Victim1234!"}` |
| 응답 | `{"accessToken": "eyJhbGciOiJFUzI1NiIsImtpZCI6...."}` |
| 시뮬 후처리 | `decode_sub(token)` → `victim_id` 추출, `decode_jti(token)` → 로그용 jti 추출 |

auth-server가 **진짜 ES256+KMS 서명 토큰**을 발급. `jti`, `iat`, `auth_time`, `ext.LSID` 등은
`JwtIssuer`가 부여 (시뮬은 위조하지 않음).

### P1 — Victim 정상 활동 (5분간)

| 항목 | 값 | 의도 |
|---|---|---|
| 주체 | **Victim** | 일반 사용자가 앱 켜놓고 자기 데이터 확인하는 패턴 재현 |
| source IP (XFF) | `222.110.15.50` (KT residential) | 변화 없음 — 로그인했을 때와 동일 회선 |
| 사용 토큰 | P0에서 발급된 access_token 그대로 | 정상 사용자가 자기 토큰 들고 쓰는 것 |
| endpoint 분포 | `/api/users/me` 70% · `/api/orders/{sub}` 20% · `/api/addresses/{sub}` 10% | "me는 자주, 민감 정보는 가끔" — 일반 사용 패턴 |
| path의 user_id | 항상 자기 user_id (`victim_id == sub`) | IDOR 활용 없음, 자기 자원만 조회 |
| 호출 간격 | `random.uniform(15, 45)` 초 | 사람이 화면 보면서 천천히 누르는 페이스 |
| 5분간 총 호출 | 평균 약 7~13건 (간격 평균 30초) | baseline 활동량 |
| HTTP 헤더 | `Authorization: Bearer {token}` + `XFF: 222.110.15.50` | |

**로그상**:
- 같은 jti가 5분간 1개 IP에서만 사용됨
- `/api/addresses` 비율 ~10%
- 호출 간격 표준편차 작음

**UBA 점수 기대치**: 모든 factor 0점 (정상 baseline 형성)

### P2 — Attacker 탈취 후 burst (수십 초)

| 항목 | 값 | 의도 |
|---|---|---|
| 주체 | **Attacker** | XSS/MITM/저장소 탈취 등으로 토큰 가로챈 공격자 |
| source IP (XFF) | `101.235.1.77` (Public WiFi / Cafe) | **회선 점프** — KT 가정 → 카페 공용망 |
| 사용 토큰 | P0에서 발급된 **동일 access_token** | 탈취한 토큰 그대로 재사용. 위조 X. |
| endpoint 분포 | `/api/addresses/{sub}` · `/api/orders/{sub}` · `/api/users/me` 균등 (`random.choice`) | 민감 정보 위주 추출. `/api/addresses` 비율 10% → ~33% 급증 |
| path의 user_id | victim 본인 user_id | victim 자기 자원만 조준 (IDOR 활용 X) |
| 호출 간격 | `random.uniform(2, 5)` 초 | 자동화 burst (사람 페이스 아님) |
| 총 호출 | `--burst 8` 기본 → 약 15~30초 안에 8건 | |
| HTTP 헤더 | `Authorization: Bearer {token}` + `XFF: 101.235.1.77` | |

### P1 vs P2 비교 (탐지 시그널)

| 차원 | P1 (Victim) | P2 (Attacker) | 신호 |
|---|---|---|---|
| Authorization | 동일 token | **동일 token** | jti 일치 |
| source IP | `222.110.15.50` | `101.235.1.77` | **회선/ASN 점프** |
| 회선 종류 | KT residential | Public WiFi | baseline 일탈 |
| 호출 간격 | 평균 30초 | 평균 3.5초 | **페이스 z-score 폭증** |
| `/api/addresses` 비율 | 10% | ~33% | **민감 endpoint 비율 급증** |
| 호출량(시간 정규화) | 분당 2건 | 분당 ~20건 | **요청율 급증** |

### UBA 5분 윈도우 관측

```
[t=0~5min]
  source AS = {KT residential}
  jti별 IP 다양성 = 1
  /api/addresses 비율 = 10%
  점수: 0

[t=5~10min]  ← P2가 여기에 들어옴
  source AS = {KT residential, Public WiFi}   ← 같은 jti, 2개 IP
  jti별 IP 다양성 = 2                          ← F-TokenHijack 폭발
  /api/addresses 비율 = ~33%                   ← F-Resp High
  호출 페이스 z-score 큼                       ← F-Burst
```

### 기대 탐지 흐름

1. `F-TokenHijack`: 동일 jti가 5분 내 ≥2개 IP에서 관측 → **raw 100**
2. ASN class 점프 (KT residential → Public WiFi) → **×1.5** 가중치
3. `/api/addresses` 응답 민감도 High → `F-Resp` **70** 결합
4. `final_score ≥ 90` → **Slack 즉시 알람**
5. (선택) Haiku 인시던트 리포트 자동 생성

### 한 줄 요약

**"같은 토큰, 다른 회선, 다른 페이스"** — P1과 P2 사이에서 변하지 않는 건 토큰 하나뿐이고
(서명·jti·sub 동일), 변하는 건 source IP·호출 페이스·민감 endpoint 비율. 이게 토큰 탈취 후
사용 패턴의 본질.

---

## S4 — 서명키 탈취 + 즉시 Enumeration

파일: `scenarios/s4_enumeration.py`

### 전체 타임라인

```
t=0 ─────────────────────── 1초 1건 페이스 ───────────────────────── t=15~30min
 │                                                                          │
 │  pool[0]=140000002 ──→ pool[1]=140000003 ──→ ... ──→ pool[N-1]=140000499 │
 │       │                       │                              │           │
 │       forge_token(2)          forge_token(3)                 forge_token(N) (모두 새 jti)
 │       GET /api/addresses/2    GET /api/addresses/3            ...        │
 │       XFF=15.164.10.40        XFF=15.164.10.40                XFF 동일   │
 │                                                                          │
 └─ duration 도달 or pool 소진까지 단조 순회 ──────────────────────────────────┘
```

단일 단계 시나리오. victim/attacker 구분 없음 — 공격자 단독.

### 주체와 행위

| 항목 | 값 | 의도 |
|---|---|---|
| 주체 | **Attacker** (서명키 탈취 후 단일 VPS 운영) | 키만 손에 쥐고 즉시 풀 전체를 긁는 "고전적 enumeration" |
| source IP (XFF) | `S4_SOURCE_IP = 15.164.10.40` — **AWS Seoul AS16509** 단일 | 단일 클라우드 인스턴스에서 운영 |
| endpoint | `/api/addresses/{sub}` 단일 | 현관비번+주소+전화+이름 묶음 (가장 민감) |
| 토큰 위조 | `forge_token(sub, ttl=600)` — **매 호출마다 새 jti** | jti 기반 동일 토큰 재사용 탐지 회피 |
| victim 풀 | `get_sequential_pool()` — `140000002 → 140000499` 순차 | enumeration 시 sub 단조 증가 |
| sub-path 매칭 | 토큰의 `sub` == path의 `user_id` 항상 일치 | 정상 사용자 위장 (sub 변조 탐지 회피) |
| 호출 페이스 | `rps=1.0` → 1초당 1건 = 분당 60건 | 빠르지만 rate-limit 피하는 페이스 |
| 가동 시간 | 30분 (시연 15분) | 약 1,800건 (`--duration 30 --rps 1.0`) |

### 매 호출의 HTTP

```http
GET /api/addresses/140000002 HTTP/1.1
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Im..."  ← 매번 jti만 새로
X-Forwarded-For: 15.164.10.40
```

### 로그상 관측 패턴

- 1개 IP에서 분당 60건 호출 — 매우 빠른 페이스
- `/api/addresses` 100% (다른 endpoint 0%)
- sub 순차 증가 (`140000002, 003, 004, ...`)
- 매 호출 새 jti (jti 다양성 폭증)
- ASN class: `AWS Seoul` (cloud_external) — 일반 사용자에게 거의 없는 회선

### 시간 추이별 UBA 점수 기대

| 시점 | 신호 | 점수 |
|---|---|---|
| t=0~1min | 5분 윈도우 미달 — baseline 기간 | 0 |
| t=5min | **IP-사용자다양성(5분) override → 100** (1 IP × 300 sub) | Slack 즉시 |
| t=5min | `/api/addresses` 비율 100% → F-Resp 70 | combined ≥ 90 |
| t=5min | ASN class = cloud_external (드문 회선) → ×1.2~1.5 | |
| t=5~30min | sub 단조성 추가 가중 (sub_id increment pattern) | |
| **MTTD 목표** | **5~15분** | |

### 핵심 메시지

**"단일 IP에서 빠른 페이스로 풀 전체를 단조 순회"** — 가장 흔하고 가장 잡기 쉬운 패턴.
UBA의 1차 방어선 검증용. S5/S6는 이 패턴을 회피하는 변종.

---

## S5 — IP 분산 + sub 순차

파일: `scenarios/s5_distributed.py`

### 전체 타임라인

```
t=0 ───────────── 1초 1건 페이스 (S4와 동일) ──────────────── t=~8min
 │                                                                  │
 │ sub=140000002 → 003 → 004 → ... → 499  (sub는 풀 1회 순차 순회)  │
 │     │              │              │                              │
 │     IP=rand(pool)  IP=rand(pool)  IP=rand(pool)                  │
 │                                                                  │
 └─ 총 498건. duration 주면 페이스 자동, 아니면 1.0s sleep ──────────┘
```

"IP만 가린 어설픈 공격자". sub는 풀을 1회 순차로 도는데 매 호출 IP만 random — 각 IP에서는
sub가 띄엄띄엄 흩어져 보이지만, 풀 전체 합산하면 sub가 단조 증가하는 게 드러남.

### 주체와 행위

| 항목 | 값 | 의도 |
|---|---|---|
| 주체 | **Attacker** (IP 풀만 가진 어설픈 공격자) | "IP는 가렸지만 sub 단조성을 빠뜨림" |
| source IP (XFF) | `lib/ip_pool.get_distributed_ips()` 풀 (4종 prefix · 옥텟 100~254) | 매 요청 random |
| IP 풀 크기 | `S5_IP_POOL_SIZE` (기본 0 → `victim_count × 0.68` 자동 ≈ 340) | 쿠팡 비율 |
| 매 요청 IP 선택 | `rng.choice(ip_pool)` | 균등 random |
| endpoint | `/api/addresses/{sub}` 단일 | S4와 동일 |
| 토큰 위조 | `forge_token(sub)` — 매 호출 새 jti | 키 탈취 가정 |
| victim 풀 | `get_sequential_pool()` 전체 (498명) | **순차 1회 순회** |
| **sub 선택** | **풀 1회 순차 순회** | **글로벌 sub 단조 증가** |
| 총 호출 수 | **498건 (S4와 동일)** | UBA factor 비교용 통일 |
| 페이스 | `--duration` 주면 자동, 기본 1.0s (= S4 페이스, 분당 60건) | |

### 매 호출의 HTTP

```http
GET /api/addresses/140000273 HTTP/1.1   ← sub 순차 (272 → 273 → 274 → ...)
Authorization: Bearer ...               ← 새 jti
X-Forwarded-For: 45.32.118.214          ← random IP from pool
```

### 로그상 관측 패턴

- 풀 약 340개 IP가 골고루 호출 — 각 IP당 평균 약 1.5건 (= 498/340)
- **각 IP별로 보면 sub가 띄엄띄엄 흩어짐** (한 IP가 random 시점에 random sub 받음)
- **전 IP 합산하면 sub가 단조 증가** (140000002 → 003 → ... → 499)
- `/api/addresses` 100%, jti는 호출 수만큼 다양

### S4 / S5b와의 비교

| 차원 | S4 (단일 IP, sub 순차) | **S5 (IP 분산, sub 순차)** | S5b (둘 다 분산) |
|---|---|---|---|
| 총 호출 수 | 498건 | **498건** | 498건 |
| 호출 페이스 | 1.0s | **1.0s (기본)** | 1.0s (기본) |
| IP 다양성 (전 구간) | 1 | ~340 | ~340 |
| 각 IP에서 본 sub 다양성 | 전부(순차) | **1~2건 평균** | 1~2건 평균 |
| **글로벌 sub 시퀀스 패턴** | **단조** | **단조** (사각지대 아님) | random (회피) |
| jti 재사용 | X (매번 새 jti) | X | X |

### 시간 추이별 UBA 점수 기대

| 시점 | 신호 | 점수 |
|---|---|---|
| t=0~5min | 단일 IP 5분 윈도우 다양성 → 0점 (회피됨) | 0 |
| t=N min | **글로벌 sub-시퀀스 단조 패턴 detect** | 70~100 |
| `F-FirstSeen-Sensitive` (신규 IP × `/api/addresses`) | 발동 기대 | 70~100 |

### 핵심 메시지

**"IP만 가렸지만 sub 시퀀스를 빠뜨린 어설픈 공격자"** — UBA의 글로벌 sub-시퀀스 factor가
잡아내야 하는 시나리오. 단일 IP factor만 있는 시스템은 사각지대지만, 글로벌 시퀀스 분석을
추가하면 잡힘. **글로벌 시퀀스 factor의 필요성 입증**.

---

## S5b — IP 분산 + sub random

파일: `scenarios/s5b_distributed_random.py`

### 전체 타임라인

```
t=0 ────────── 매 요청 random victim × random IP ────────── t=~8min
 │                                                                  │
 │ req#1   victim=rand(pool)   ip=rand(ip_pool)   forge_token(...) │
 │ req#2   victim=rand(pool)   ip=rand(ip_pool)   forge_token(...) │
 │   ...                                                            │
 │ req#498 (= victim_count, S4·S5와 동일 총량)                     │
 │                                                                  │
 └─ duration이 주어지면 페이스 자동, 아니면 1.0s sleep (S4 페이스) ──┘
```

쿠팡 사고의 **분포 구조**(매 요청 victim/IP 모두 random)를 비례 축소해 재현. 호출량 자체는
S4/S5와 통일(498건)해서 UBA factor 차이를 깨끗하게 비교. **완전 분산 botnet** — IP/sub 모두 random.

### 주체와 행위

| 항목 | 값 | 의도 |
|---|---|---|
| 주체 | **Attacker** (botnet/VPS 풀 다수 운영) | "한 IP가 여러 계정, 한 계정이 여러 IP" — 쿠팡 분포 |
| source IP (XFF) | S5와 동일 (4종 prefix 풀 random) | 매 요청 random |
| IP 풀 크기 | S5와 동일 (~340) | |
| endpoint | `/api/addresses/{sub}` 단일 | |
| 토큰 위조 | `forge_token(sub)` — 매 호출 새 jti | 키 탈취 가정 |
| **sub 선택** | **`rng.choice(victims)` — 매 요청 균등 random** | 쿠팡 실측 분포 |
| 총 호출 수 | **498건 (S4·S5와 동일)** | 호출량 통일 |
| 페이스 | `--duration` 주면 자동, 기본 1.0s (= S4 페이스) | |

### 매 호출의 HTTP

```http
GET /api/addresses/140000273 HTTP/1.1   ← random sub
Authorization: Bearer ...               ← 새 jti
X-Forwarded-For: 45.32.118.214          ← random IP from pool
```

### 로그상 관측 패턴

- IP 풀 ~340개 골고루 — 각 IP당 평균 약 1.5건 (= 498/340)
- **매 요청마다 sub random** — 순차 패턴 없음
- 계정당 평균 약 1건 (중복 추출로 0~3건 분산)
- 글로벌 시퀀스 분석해도 sub random 분포 — 단조성 없음

### S5와 S5b의 결정적 차이

| 차원 | S5 (sub 순차) | **S5b (sub random)** |
|---|---|---|
| 총 호출 수 | 498건 | 498건 (동일) |
| 글로벌 sub 시퀀스 | 단조 (잡힘) | **random (회피)** |
| 잡히는 factor | 글로벌 시퀀스 + FirstSeen | **FirstSeen 등 보완 factor만** |
| 회피 수준 | 중급 (글로벌 시퀀스에 약함) | **최강 (보완 factor 없으면 미탐)** |

### 시간 추이별 UBA 점수 기대 (사각지대 시나리오)

| 시점 | 신호 | 점수 |
|---|---|---|
| t=0~5min | 단일 IP 5분 윈도우 다양성 → 0점 | 0 |
| t=N min | 글로벌 sub-시퀀스 단조 → 0점 (random이라 단조 패턴 없음) | 0 |
| **F-FirstSeen-Sensitive** (신규 IP × 민감 endpoint) | 발동 기대 | 70~100 |

### 핵심 메시지

**"완전 분산 — 단일 IP factor도 글로벌 시퀀스 factor도 못 잡음"**. FirstSeen / 신규 IP 같은
보완 factor 없으면 탐지 사각지대. **보완 factor의 필요성을 데이터로 보여주는 끝판왕 시나리오**.

S5와 S5b를 함께 시연하면, UBA factor의 단계적 효과(단일 IP → 글로벌 시퀀스 → FirstSeen)
를 한 줄로 입증 가능. 세 시나리오가 같은 호출량(498건) · 같은 페이스(1.0s)로 통일되어 있으므로
factor 발동 여부의 차이가 곧 회피 전략의 차이로 환원된다.

---

## S6 — Slow & Low + Impossible Travel

파일: `scenarios/s6_slow_low.py`

### 전체 타임라인

```
t=0 ──── 30~60s sleep ──── ... ──── 분당 1~2건 ──── ... ──── t=6h ─── ... ─── t=24h
 │                                                                                  │
 │ pool[0] (random shuffle)                                                          │
 │   GET /api/addresses/{shuffled[0]}                                                │
 │   XFF=98.138.10.66 (US Residential)                                               │
 │                                                                                   │
 │ ──┴── 30~60s sleep ──┬──                                                          │
 │                                                                                   │
 │ pool[1]                                                                           │
 │   ...                                                                             │
 └─ duration 도달 or pool 소진까지 ─────────────────────────────────────────────────┘
```

S4와 동일 메커니즘(단일 IP, 키 위조)인데 **시간을 7개월 늘인 변형**. 추가로 **US 가정 IP**라
한국 사용자 풀에 대한 Impossible Travel.

### 주체와 행위

| 항목 | 값 | 의도 |
|---|---|---|
| 주체 | **Attacker** (해외 가정 회선 또는 그 회선 봇넷 일부) | 7개월 미탐지 재현 |
| source IP (XFF) | `S6_SOURCE_IP = 98.138.10.66` — **US Residential** 단일 | 한국 사용자(`140000xxx`) 풀과 지리적 이상 |
| endpoint | `/api/addresses/{sub}` 단일 | S4와 동일 |
| 토큰 위조 | `forge_token(sub)` — 매 호출 새 jti | 키 탈취 가정 |
| victim 풀 | `get_shuffled_pool(seed=42)` — 랜덤 셔플 | sub 단조 증가 패턴 숨김 |
| 호출 페이스 | `random.uniform(30, 60)` 초 sleep = 분당 1~2건 | **5분 윈도우 z-score 미달** |
| 가동 시간 | 24시간 (시연 6시간 압축) | 약 1,440~2,880건 |

### 매 호출의 HTTP

```http
GET /api/addresses/140000337 HTTP/1.1   ← shuffled 순서
Authorization: Bearer ...               ← 새 jti
X-Forwarded-For: 98.138.10.66           ← 미국 가정 IP 단일
```

### 로그상 관측 패턴

- 1개 IP에서 분당 1~2건 — S4 페이스의 1/30~1/60
- 매 호출 sub 다름 (shuffled) — 순차 패턴 없음
- `/api/addresses` 100% (S4와 동일)
- ASN class = **US Residential (Comcast 류)** — 한국 사용자 풀과 지리적 이상

### S4와의 차이 (시간 차원)

| 차원 | S4 (즉시) | S6 (slow) |
|---|---|---|
| 분당 호출 | 60 | 1~2 |
| sub 순서 | 순차 | shuffled |
| 5분 윈도우 다양성 | 폭발 (raw 100) | **미달 (0점)** |
| ASN 지리 | AWS Seoul (한국 내) | US Residential (한국 사용자 풀에 대한 외국 IP) |
| 가동 시간 | 30분 | 24시간 |
| 총 유출량 | ~1,800건 | ~1,440~2,880건 (유사) |

### 시간 추이별 UBA 점수 기대 (장기 윈도우 검증)

| 시점 | 신호 | 점수 |
|---|---|---|
| t=0~1h | 5분 윈도우 미달 → 모든 신호 0점 (의도된 사각지대) | 0 |
| t=1h | **1시간 윈도우 의심 단계** | 70 |
| t=24h | **24시간 윈도우 override → 100** + 누적유출량 z-score 폭증 | 100 |
| 전 구간 | `F-ImpossibleTravel`: 한국 사용자 토큰 × 미국 IP 지속 조회 | 가중치 추가 |
| **MTTD 목표** | **수 시간 ~ 24h** | |

### 핵심 메시지

**"천천히, 그러나 꾸준히"** — 5분 윈도우만 보면 안 잡힌다. **장기 윈도우 + 지리적 이상**으로
잡아야 함. UBA의 멀티 윈도우 설계와 ImpossibleTravel factor 필요성 입증.

---

## 시나리오 간 공통 요약 표

| 시나리오 | 주체 분리 | source IP | sub 패턴 | endpoint 분포 | 호출 페이스 | 토큰 방식 | 핵심 회피/탐지 차원 |
|---|---|---|---|---|---|---|---|
| **S2** | victim P1 / attacker P2 | victim_ip → attacker_ip | victim 본인 1명 | me 70/orders 20/addr 10 → 균등 | P1 30s · P2 3.5s | **진짜 토큰** (auth-server) | jti 동일 × IP 다름 |
| **S4** | attacker 단독 | 단일 (AWS Seoul) | 순차 1회 순회 (498건) | `/api/addresses` 100% | 1.0s | forge_token (새 jti) | 단일 IP × 다수 sub |
| **S5** | attacker 단독 | 340개 풀 random | **순차 1회 순회 (498건)** | `/api/addresses` 100% | 자동 / 1.0s | forge_token (새 jti) | IP만 분산 — **글로벌 sub 시퀀스에 잡힘** |
| **S5b** | attacker 단독 (botnet) | 340개 풀 random | **random per request (498건)** | `/api/addresses` 100% | 자동 / 1.0s | forge_token (새 jti) | **완전 분산 — 보완 factor만 잡음** |
| **S6** | attacker 단독 | 단일 (US Residential) | shuffled | `/api/addresses` 100% | 30~60s sleep | forge_token (새 jti) | **시간 분산 + Impossible Travel** |

---

## 검토 포인트 체크리스트

코드 수정 지시 전에 본 문서에서 확인하고 싶을 것들:

- [ ] **S2**: P1/P2의 endpoint 가중치, 호출 간격, burst 횟수가 의도와 맞는지
- [ ] **S2**: victim의 IDOR 활용 여부 (현재 X — victim 자기 자원만 조회)
- [ ] **S4**: 풀 순차 vs shuffled (S4=순차, S6=shuffled — 패턴 차이 확실한지)
- [ ] **S4**: `--rps 1.0` 페이스가 적정한지 (분당 60건 = 풀 498건을 ~8분에 소진)
- [ ] **S5/S5b**: 호출량이 S4와 동일하게 498건(풀 1회)으로 통일되어 있는지 — UBA factor 비교 시 변량을 IP/sub 선택 전략 하나로만 좁히려는 의도
- [ ] **S5**: 풀 1회 순차 순회로 글로벌 sub 단조 패턴이 잡힐 만큼 신호가 충분한지 (498건 단일 cycle)
- [ ] **S5b**: 매 요청 균등 random이 맞는지, 다른 전략(예: 같은 IP가 잠깐 같은 sub 군집 조회) 필요한지
- [ ] **S6**: 6시간 압축 시연 시 24시간 윈도우 신호가 발동 가능한지 (시뮬 시간 ≠ 윈도우 시간)
- [ ] **S6**: Impossible Travel 발동을 위한 victim 풀-IP 지리 정보 매핑 정책
- [ ] **공통**: 모든 시나리오가 같은 ALB DNS로 가는지, auth-server 호출은 S2만인지
- [ ] **공통**: 어떤 cwd에서 실행해도 동작하는 환경(`.env` / `LEAKED_KEY_PATH` 자동 root 보정)이 의도와 맞는지
