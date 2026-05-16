# attack-payload

쿠팡 2024 사고를 모티브로 한 **JWT 위조 + Enumeration / Token Hijacking 공격 시뮬레이터**.
ZETI 백엔드(API/Auth) 앞단의 ALB → Nginx → API 흐름에 위조 트래픽을 흘려, 추후 구축할 UBA(User
Behavior Analytics) 엔진의 탐지 factor를 검증하기 위한 도구다.

> 본 시뮬은 **자체 인프라(테스트 ALB DNS)** 만 대상으로 한다. 외부 시스템에 절대 사용 금지.

---

## 1. 디렉토리 구조

```
attack-payload/
├── .env.example          # 환경변수 템플릿 (개인 .env로 복사)
├── requirements.txt
├── run.sh                # 발표 시연용 일괄 실행 (S4 + S6 기본)
├── leaked-key/
│   ├── pkcs8_private_key.pem   # 유출 가정 ES256 개인키 (Git 금지)
│   ├── pkcs8_private_key.der   # KMS BYOK import용 (Git 금지)
│   └── README.md
├── lib/
│   ├── http_client.py    # 공통 HTTP wrapper (XFF 위조 + 재시도)
│   ├── ip_pool.py        # 분산 IP 풀 생성 (S5용)
│   ├── target_pool.py    # victim sub 풀 (sequential / shuffled)
│   └── token_forge.py    # JWT ES256 위조 (forge_token / forge_token_with_jti)
└── scenarios/            # 공격 시나리오 (각각 단독 실행 가능)
    ├── s2_token_hijack.py            # JWT 토큰 하이재킹 (진짜 로그인 기반)
    ├── s4_enumeration.py             # 서명키 탈취 + 즉시 enumeration
    ├── s5_distributed.py             # 분산 enumeration — IP 분산, sub 순차
    ├── s5b_distributed_random.py     # 분산 enumeration — IP 분산, sub random
    └── s6_slow_low.py                # Slow & Low + Impossible Travel
```

---

## 2. 사전 준비

```bash
pip install -r requirements.txt
cp .env.example .env       # 개인 환경값으로 수정
# leaked-key/README.md 따라 ES256 개인키 생성 (시뮬 전용)
```

`.env` 핵심 값:

| 변수 | 의미 |
|---|---|
| `ZETI_ALB_URL` | 공격 대상 ALB DNS (모든 시나리오 공통, S2는 `/auth/login`도 동일 경로) |
| `LEAKED_KEY_PATH` | **S4/S5/S6용** 위조 서명 개인키 경로 (S2는 사용 안 함) |
| `KID` | KMS alias (위조 서명 헤더 `kid`로 박힘) |
| `VICTIM_SUB_START` / `VICTIM_SUB_END` | enumeration 풀 범위 (기본 140000002~140000500, 498명) |
| `VICTIM_EMAIL` / `VICTIM_PASSWORD` | **S2 전용**, 운영 RDS에서 골라온 실계정 credentials |
| `S4_SOURCE_IP` 외 | 시나리오별 XFF 위조용 source IP (아래 IP 색깔 매트릭스 참고) |
| `S5_IP_POOL_SIZE` | S5/S5b 분산 IP 풀 크기 (0이면 `victim_count × 0.68` 자동) |

---

## 3. 시나리오 한눈에 보기

| ID | 이름 | source IP (prefix) | endpoint | 페이스 | 가동 시간 | 풀 | 패턴 |
|---|---|---|---|---|---|---|---|
| **S2** | Token Hijack | victim `222.110.15.50` (KT residential) → attacker `101.235.1.77` (Public WiFi / Cafe) | `/api/users/me`, `/api/orders/{sub}`, `/api/addresses/{sub}` | 1단계: 15~45s sleep / 2단계: 2~5s burst | 1단계 5분 + 2단계 ~30초 | 단일 victim 1명 | **같은 jti** 공유, 회선 점프 (집 → 카페) |
| **S4** | Enumeration | `15.164.10.40` (AWS Seoul) 단일 | `/api/addresses/{sub}` | 1.0 RPS (분당 60건) | ~8분 (498건) | 498명 sequential | 단일 클라우드 인스턴스에서 기계적 열거 |
| **S5** | Distributed Enum (IP 분산, sub 순차) | 4종 prefix 풀 ~340개 (random per request) | `/api/addresses/{sub}` | `--duration` 주면 자동, 기본 1.0s | 498건 (풀 1회 순회) | 498명 sequential | **IP만 분산, sub는 풀 1회 순차 순회** (어설픈 공격자) |
| **S5b** | Distributed Enum (IP+sub random) | 위 동일 풀, random per request | `/api/addresses/{sub}` | 위 동일 | 498건 (sub random) | 498명 (매번 random) | **매 요청 victim/IP 모두 random** (쿠팡 분포) |
| **S6** | Slow & Low | `98.138.10.66` (US Residential / Comcast 류) 단일 | `/api/addresses/{sub}` | 30~60s sleep (분당 1~2건) | 24시간 (시연 6h) | 498명 shuffled | 낮은 빈도 + **Impossible Travel** (한국 사용자 풀을 미국 IP로 조회) |

### IP 색깔 매트릭스 (실전 ASN 기반, prefix만 봐도 시나리오 식별)

| prefix | 시나리오 | 실제 ASN 성격 (탐지 레이블) |
|---|---|---|
| `15.x`   | S4 | **AWS Asia Pacific (Seoul)** AS16509 — 단일 클라우드 인스턴스 |
| `98.x`   | S6 | **US Residential** (Comcast 류) — 해외 가정용, Impossible Travel 유도 |
| `222.x`  | S2 victim | **KT Corporation** AS4766 — 집 KT 인터넷 |
| `101.x`  | S2 attacker | **Public WiFi / Cafe** — SK BB 류 공용망 (탈취 토큰 사용처) |
| `203.0.113` / `198.51.100` / `192.0.2` / `45.32.x` (옥텟 **100~254**) | S5 풀 | **Mixed Hosting / VPS** — Vultr + 시뮬용 placeholder |

> 단일 IP 시나리오는 마지막 옥텟 **1~99**(50/77/40/66), S5 풀은 **100~254**로 강제 분리되어 충돌 0.

---

## 4. 시나리오 상세

### S2 — JWT 토큰 하이재킹 (`scenarios/s2_token_hijack.py`)

**시나리오 서사**: 사용자가 정상 KT 가정 인터넷에서 `/auth/login`으로 로그인 → auth-server가
ES256 + KMS 서명으로 **진짜 access token** 발급. 그 토큰이 (XSS / MITM / 토큰 저장소 탈취 등으로)
공격자에게 넘어가, 카페·공용망(Public WiFi)에서 같은 토큰으로 민감 정보를 burst 조회.

> **다른 시나리오와의 차이**: 본 시나리오는 `forge_token` 사용 X. auth-server가 진짜 발급한
> 토큰을 그대로 사용. 즉 서명·jti·iat 모두 운영 발급치와 동일하며, 차이는 **source IP뿐**.
> "키 자체를 탈취해 임의 sub로 위조하는" S4와는 공격 벡터가 명확히 분리된다.

| 항목 | 값 |
|---|---|
| victim 계정 | `.env`의 `VICTIM_EMAIL` / `VICTIM_PASSWORD` (운영 RDS에서 골라온 실계정) |
| 토큰 획득 | `POST {ZETI_ALB_URL}/auth/login`, body `{email, password}`, **XFF = victim IP** |
| victim_id (sub) | 발급된 토큰 payload의 `sub` 클레임 그대로 사용 (path에도 동일) |
| **1단계 — Victim 정상 활동** | |
| ↳ source IP (XFF) | `VICTIM_SOURCE_IP = 222.110.15.50` — **KT Corporation (AS4766)** |
| ↳ 사용 토큰 | 1단계에서 발급된 진짜 token 그대로 |
| ↳ endpoint 가중치 | `/api/users/me` (7) / `/api/orders/{sub}` (2) / `/api/addresses/{sub}` (1) |
| ↳ 간격 | `random.uniform(15, 45)` 초 |
| ↳ 지속 | 5분 (`--victim-minutes`) |
| **2단계 — Attacker burst** | |
| ↳ source IP (XFF) | `ATTACKER_SOURCE_IP = 101.235.1.77` — **Public WiFi / Cafe** |
| ↳ 사용 토큰 | **1단계와 동일한 access token** (탈취 시뮬) |
| ↳ endpoint 풀 | `/api/addresses/{sub}`, `/api/orders/{sub}`, `/api/users/me` (random) |
| ↳ 간격 | `random.uniform(2, 5)` 초 |
| ↳ 횟수 | 8건 (`--burst`) |

**기대 탐지 신호** *(UBA 구축 시 검증할 factor)*:
- `F-TokenHijack`: **동일 jti(또는 access token hash)** 가 5분 내 서로 다른 IP/ASN에서 관측 → raw 100
- 회선 점프 (KT residential → Public WiFi) → 평소 사용자 baseline에서 벗어남 → 가중치 1.5×
- 응답 민감도 High (`/api/addresses`) `F-Resp` 70 결합 → `final_score ≥ 90`

**사전 준비**:
1. AWS RDS에서 적당한 user 계정 한 명 선정 (또는 그 계정의 password를 알려진 값으로 update)
2. `.env`의 `VICTIM_EMAIL` / `VICTIM_PASSWORD`에 해당 credentials 박기
3. ALB 라우팅이 `POST /auth/login` → auth-server로 가는지 확인

**실행**:
```bash
python scenarios/s2_token_hijack.py --victim-minutes 5 --burst 8
```

---

### S4 — 서명키 탈취 + 즉시 Enumeration (`scenarios/s4_enumeration.py`)

**시나리오 서사**: 공격자가 KMS 외부 alias 키를 탈취해 즉시 **AWS Seoul EC2 인스턴스**에서
victim 풀을 순차로 긁어내려는 "고전적 enumeration".

| 항목 | 값 |
|---|---|
| source IP (XFF) | `S4_SOURCE_IP = 15.164.10.40` — **AWS Asia Pacific (Seoul) AS16509** 단일 |
| endpoint | `/api/addresses/{sub}` 단일 (현관비번+주소+전화+이름 묶음) |
| 토큰 위조 | `forge_token(sub, ttl=600)` — **매 호출마다 새 jti** (jti 기반 탐지 회피) |
| 페이스 | `rps=1.0` → 1초당 1건 = 분당 60건 |
| 가동 시간 | 30분 (시연 15분) |
| victim 풀 | `get_sequential_pool()` — 140000002 → 140000500 순차 |

**기대 탐지 신호**:
- t=05:00, **IP-사용자다양성(5분 윈도우) override 100** → Slack 즉시
- t=05:30, Haiku 인시던트 리포트 발행 (MTTD 5~15분 목표)
- 단일 IP에서 단시간 다수 sub 조회 → `F-DiversityIPSub` raw 100

**실행**:
```bash
python scenarios/s4_enumeration.py --duration 15 --rps 1.0
```

---

### S5 / S5b — 분산 Enumeration (두 변종)

쿠팡 사고(2,300 IP × 3,367 계정, IP : 계정 ≈ 0.68 : 1)의 IP 분포 구조를 비례 축소해
재현하되, **호출 방식 자체는 S4와 통일**(풀 크기 = 498건, 1초 간격)해 UBA factor의
차이를 깨끗하게 비교한다. **공격자의 회피 수준**만 두 변종으로 분리:

| 변종 | 파일 | IP | sub 선택 | 회피하지 못하는 신호 |
|---|---|---|---|---|
| **S5** (어설픈 공격자) | `scenarios/s5_distributed.py` | 풀 random | **순차 1회 순회** | **풀 합산 sub 단조 패턴** (글로벌 시퀀스 factor에 잡힘) |
| **S5b** (완전 분산 botnet) | `scenarios/s5b_distributed_random.py` | 풀 random | **random per request** | `F-FirstSeen-Sensitive` 등 보완 factor |

공통 사항:
- source IP 풀: `lib/ip_pool.get_distributed_ips()` — `203.0.113`(/24) · `198.51.100`(/24) · `192.0.2`(/24) · `45.32.x`(/16, Vultr), 옥텟 **100~254**
- IP 풀 크기: `S5_IP_POOL_SIZE` (기본 0 → `victim_count × 2300/3367 ≈ 0.68` 자동 = 약 340)
- 총 호출 수: **498건** (S4와 동일, 풀 크기 = `VICTIM_SUB_END - VICTIM_SUB_START`)
- endpoint: `/api/addresses/{sub}` 단일
- 토큰: `forge_token(sub)` — 매 호출 새 jti (서명키 탈취 가정)
- 페이스: `--duration N`(분) 주면 자동, 기본 1.0s (S4와 동일, 분당 60건, ~8분 소요)

#### S5 — IP 분산, sub 순차

`victims = [140000002 .. 140000499]` 풀을 **1회 순차 순회**. 매 호출의 IP는 풀에서 random
추출. **각 IP에서는 sub가 random하게 흩어져 보이지만, 글로벌 시퀀스(전 IP 합산)를 합치면
sub가 단조 증가**.

**기대 탐지**: 단일 IP 다양성 → 0점 / **글로벌 sub-시퀀스 factor가 잡아야 함**.
"IP만 가린 어설픈 공격자" 메시지. UBA의 글로벌 시퀀스 분석 능력 검증용.

```bash
python scenarios/s5_distributed.py                  # 기본 (interval 1.0s, ~8분)
python scenarios/s5_distributed.py --duration 30    # 30분 안에 끝내기
python scenarios/s5_distributed.py --interval 0.2   # 짧게 빠르게
```

#### S5b — IP 분산 + sub random (완전 분산)

매 요청마다 victim/IP 모두 `rng.choice()`. **단일 IP factor도, sub 시퀀스 factor도 못 잡음**.
FirstSeen 같은 보완 factor 없으면 탐지 사각지대 — 그 사각지대를 데이터로 입증.

**기대 탐지**: 단일 IP 다양성 → 0점 / 글로벌 시퀀스도 → 0점 / **F-FirstSeen-Sensitive 등 보완 factor만 발동 기대**.
"완전 분산 botnet" 메시지. 보완 factor 필요성 입증.

```bash
python scenarios/s5b_distributed_random.py
python scenarios/s5b_distributed_random.py --duration 30
python scenarios/s5b_distributed_random.py --interval 0.2
```

---

### S6 — Slow & Low + Impossible Travel (`scenarios/s6_slow_low.py`)

**시나리오 서사**: 쿠팡 7개월 미탐지 재현 + **지리적 이상 징후**. 단일 IP(미국 가정용 회선)
에서 **분당 1~2건**으로 천천히 긁어, 5분 윈도우 z-score는 미달시키되 — 한국 사용자 풀
(`140000xxx`)을 **해외 미국 IP**로 조회하는 패턴이 누적되어 Impossible Travel factor를 유발.

| 항목 | 값 |
|---|---|
| source IP (XFF) | `S6_SOURCE_IP = 98.138.10.66` — **US Residential** (Comcast 류) **단일** |
| endpoint | `/api/addresses/{sub}` 단일 |
| 토큰 위조 | `forge_token(sub)` — 매 호출 새 jti |
| 페이스 | `random.uniform(30, 60)` 초 sleep — 분당 1~2건 |
| 가동 시간 | 24시간 (시연 6시간 압축) |
| victim 풀 | `get_shuffled_pool(seed=42)` — 랜덤 셔플로 순차 패턴 숨김 |

**기대 탐지 신호**:
- 첫 1시간: 5분 윈도우 미달 → 모든 신호 0점 (의도된 사각지대)
- t=01:00 1시간 윈도우 의심 단계 (70)
- t=24:00 **24시간 윈도우 override 100 + 누적유출량 z-score 폭증**
- **F-ImpossibleTravel**: 한국 사용자(`140000xxx`) 토큰을 미국 IP(`98.138.10.66`)에서
  지속 조회 → 지리적 이상 → 추가 가중치
- MTTD 목표: 수 시간 ~ 24h

**실행**:
```bash
python scenarios/s6_slow_low.py --duration 6 --min-interval 30 --max-interval 60
```

---

## 5. 실행 방법

각 시나리오는 **단독 Python 실행**이 기본. 어떤 cwd에서 실행해도 작동하도록 `.env` 경로와
`LEAKED_KEY_PATH` 상대 경로가 attack-payload root 기준으로 자동 해석된다.

```bash
# attack-payload 디렉토리에서:
python scenarios/s2_token_hijack.py --victim-minutes 5 --burst 8
python scenarios/s4_enumeration.py --duration 15 --rps 1.0
python scenarios/s5_distributed.py --duration 30
python scenarios/s5b_distributed_random.py --duration 30
python scenarios/s6_slow_low.py --duration 6 --min-interval 30 --max-interval 60
```

`run.sh`는 발표용 일괄 실행(S4+S6 병렬 데모) 옵션으로만 남겨둠. 평소 검증은 위 명령으로 충분.

```bash
./run.sh demo      # S4 15분 + S6 6h 압축 (병렬, 시연용)
./run.sh full      # S4 30분 + S6 24h
```

---

## 6. XFF 위조 동작 원리 (요약)

`lib/http_client.call_api()`가 `src_ip` 인자를 받으면 `X-Forwarded-For: {src_ip}` 헤더로
요청한다. ALB가 client(시뮬 머신) IP를 **append**하므로 백엔드에 도달하는 헤더는:

```
X-Forwarded-For: <시뮬이 박은 src_ip>, <시뮬 머신 진짜 IP>, <ALB IP>
       ↑ 왼쪽 = 위조 source                          ↑ 오른쪽 = LB hop
```

Nginx의 `set_real_ip_from <ALB CIDR>` + `real_ip_recursive on` 조합에서 ALB IP를
신뢰 hop으로 건너뛰고 그 앞의 IP(시뮬 머신)를 `$remote_addr`로 박는 게 기본. **위조한
`src_ip`까지 client로 인식시키려면 시뮬 머신 IP도 `set_real_ip_from`에 포함되어야 함**.

운영 endpoint에서 권한·rate-limit 결정은 `$remote_addr` 기준이라 영향 없음. 위조의 효과는
**로그/UBA 분석 파이프라인**에서만 관찰 가능 — UBA는 `x_forwarded_for` 필드를 별도 파싱해야 함.

**UBA factor 구현 시 주의 사항** *(시뮬이 의도한 client IP를 정확히 잡으려면)*:
- 헤더는 콤마 구분된 IP 리스트 — **왼쪽 첫 번째 토큰이 시뮬의 위조 IP**.
- 만약 UBA가 "오른쪽 마지막" 또는 "$remote_addr" 한 가지만 본다면 위조가 무효화됨.
- 권장: 헤더 전체를 파싱 → `set_real_ip_from`에 포함된 신뢰 hop(ALB + 시뮬 머신 등)을
  오른쪽부터 건너뛴 첫 IP를 client IP로 인식.

운영 정책(LB/WAF/Nginx)이 단단하면 위조가 통하지 않을 수 있음. 본 시뮬은 그 정책이
**느슨하거나 시뮬 의도로 열어둔 환경**을 전제로 한다.

---

## 7. 안전 수칙

- `leaked-key/*.pem`, `*.der`는 **절대 Git 커밋 금지** (`.gitignore` 확인).
- 시뮬 종료 후 키는 보안 삭제 (`shred -u` / `sdelete`).
- 본 시뮬은 자기 소유 ZETI 테스트 인프라 외에서는 실행 금지.
