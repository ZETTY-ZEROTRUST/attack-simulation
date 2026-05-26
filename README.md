# 🎯 ZETI Attack Simulation — JWT 위조 + Enumeration + Hijacking

> **ZETI (Zero Trust + UBA) — 아주대 캡스톤 / Google × Ajou AI Capstone Design**
> 쿠팡 2024 사고를 모티브로 한 **JWT 위조 + Enumeration / Token Hijacking 공격 시뮬레이터**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](#)
[![JWT](https://img.shields.io/badge/JWT-ES256%20Forge-blueviolet.svg)](#)
[![Scenarios](https://img.shields.io/badge/Scenarios-S2%20%2B%20S4%20%2B%20S5%20%2B%20S5b%20%2B%20S6%20%2B%20S8-orange.svg)](#)
[![Safety](https://img.shields.io/badge/Use-Authorized%20Self%20Infra%20Only-red.svg)](#)

---

## ⚡ 30초 요약

ZETI 백엔드(`backend`) 의 의도된 4 취약점을 공격하는 **6 시나리오 시뮬레이터** + **lib/** 공통 모듈. 위조 트래픽이 ALB → Nginx PEP → API 흐름에 흘러 들어가, `log-pipeline` 의 ingest pipeline 이 분해·보강한 뒤 `uba-analyzer` 가 7 팩터로 잡아내는지 검증합니다. **JWT ES256 위조 / IP 분산 / XFF 위조 / Slow & Low / 토큰 하이재킹 / 장수명 토큰** 6 종.

- 🎯 **6 공격 시나리오**: S2 토큰 하이재킹 · S4 단일 IP enumeration · S5 분산 (sub 순차) · S5b 분산 (sub random) · S6 Slow&Low + Impossible Travel · S8 장수명 토큰
- 🔑 **ES256 키 위조**: KMS 외부 alias 키 탈취 가정 → `lib/token_forge.py` 로 임의 sub 토큰 생성
- 🌐 **XFF 위조 + IP 색깔 매트릭스**: AWS Seoul / KT 가정용 / 카페 / US 가정용 / VPS 풀 — prefix 만 봐도 시나리오 식별
- 📊 **쿠팡 분포 재현**: 2,300 IP × 3,367 계정 (IP:계정 ≈ 0.68:1) 비례 축소
- 🎬 **단독 시연 진입점**: `demo_s2.py` / `demo_s5.py` — 시나리오 발사 + Filebeat 색인 wait + SSM 으로 UBA pipeline+phase3a 자동 trigger
- 🚫 **자체 인프라 전용**: 외부 시스템에 절대 사용 금지

> ⚠️ **본 시뮬은 자기 소유 ZETI 테스트 인프라 외에서는 절대 실행 금지.** `leaked-key/*.pem` 도 Git 커밋 금지.

---

## 🎬 Live Demo — 발표 시연용 자동화

```bash
# 시연 1: S2 토큰 하이재킹 + 자동 UBA 분석 (~5분 후 Slack pop)
python demo_s2.py

# 시연 2: S5 IP 분산 enum + 자동 UBA 분석 (~5분 후 Slack pop)
python demo_s5.py

# 시연 일괄 (S4 15분 + S6 6h 압축 병렬)
./run.sh demo
```

| 단계 | 동작 | 소요 |
|------|------|------|
| 1 | 시나리오 발사 (콘솔에 진행 그대로) | 시나리오별 다름 |
| 2 | 시나리오 종료 wait | — |
| 3 | Filebeat → ELK 색인 wait | 30 초 |
| 4 | SSM 으로 UBA EC2 `cron_pipeline.sh` + `cron_phase3a.sh` 수동 trigger (throttle 우회) | ~1 분 |
| 5 | Slack 인시던트 리포트 pop | ~5 분 |

> **demo_*.py 의 묘미**: 운영 cron 영향 없음. `orchestrator-state.json` 을 SSM 명령 앞단에서 rm 하므로 throttle 우회 — 연속 시연 가능.

---

## 🏗️ 1. AWS 인프라 위치 — 외부에서 ALB 로 흘려보내기

```mermaid
flowchart LR
    SIM[시뮬레이터<br/>로컬 / 별도 EC2] -->|443 + XFF 위조| ALB
    subgraph VPC["ZETI VPC"]
        ALB -->|80| NGX[Nginx PEP<br/>priv-web-2a/2b]
        NGX -->|8081| API[api-server<br/>priv-app]
        NGX -.access.log.-> FB[Filebeat sidecar]
        FB -.5044.-> ELK[(ELK<br/>priv-monitor)]
    end
    ELK -->|9200| UBA[UBA Python]
    UBA -->|HTTPS| ANT[(Claude Haiku 4.5)]
    UBA -->|webhook| SLK[Slack]
```

**XFF 위조 동작 원리** (요약):
```
X-Forwarded-For: <시뮬이 박은 src_ip>, <시뮬 머신 진짜 IP>, <ALB IP>
       ↑ 왼쪽 = 위조 source                          ↑ 오른쪽 = LB hop
```
- Nginx `set_real_ip_from <ALB CIDR>` + `real_ip_recursive on` 에서 ALB IP 신뢰 hop 으로 건너뜀
- 위조한 `src_ip` 까지 client 로 인식시키려면 **시뮬 머신 IP 도 `set_real_ip_from` 에 포함**되어야 함
- 권한·rate-limit 결정은 `$remote_addr` 기준이라 영향 없음. 위조의 효과는 **로그/UBA 분석 파이프라인** 에서만

> 운영 정책 (LB/WAF/Nginx) 이 단단하면 위조가 통하지 않음. 본 시뮬은 그 정책이 **느슨하거나 시뮬 의도로 열어둔 환경** 을 전제.

---

## 🎯 2. 시나리오 한눈에 보기

| ID | 이름 | source IP (prefix) | endpoint | 페이스 | 풀 | 잡혀야 할 팩터 |
|----|------|-------------------|---------|--------|-----|---------------|
| **S2** | Token Hijack | victim `222.110.15.50` (KT) → attacker `101.235.1.77` (Cafe) | `/api/users/me`, `/api/orders/{sub}`, `/api/addresses/{sub}` | 1단계: 15~45s / 2단계: 2~5s burst | 단일 victim 1명 | `token_replay` (jti 공유 + ip_class 교차) |
| **S4** | Enumeration | `15.164.10.40` (AWS Seoul) 단일 | `/api/addresses/{sub}` | 1.0 RPS | `VICTIM_COUNT` 명 순차 | `ip_user_diversity` override → 100 |
| **S5** | Distributed (sub 순차) | 4종 prefix 풀 random | `/api/addresses/{sub}` | 1.0s | `VICTIM_COUNT` 명 순차 | **글로벌 sub 시퀀스** (Route B ASN 다양성) |
| **S5b** | Distributed (sub random) | 위 동일 풀 random | `/api/addresses/{sub}` | 1.0s | `VICTIM_COUNT` 명 랜덤 비복원 | `F-FirstSeen-Sensitive` 등 보완 factor |
| **S6** | Slow & Low | `98.138.10.66` (US Residential) 단일 | `/api/addresses/{sub}` | 30~60s sleep | `VICTIM_COUNT` 명 랜덤 | `cumulative_exfil` 24h z 폭증 + Impossible Travel |
| **S8** | 장수명 토큰 | 단일 IP | `/api/addresses/{sub}` | 정상 페이스 | victim 수 적게 | `token_violation` T007 (exp-iat>3600) → 80 |

### 🎨 IP 색깔 매트릭스 (실전 ASN 기반, prefix 만 봐도 시나리오 식별)

| prefix | 시나리오 | 실제 ASN 성격 (탐지 레이블) |
|--------|---------|---------------------------|
| `15.x`   | **S4** | **AWS Asia Pacific (Seoul)** AS16509 — 단일 클라우드 인스턴스 |
| `98.x`   | **S6** | **US Residential** (Comcast 류) — 해외 가정용, Impossible Travel 유도 |
| `222.x`  | **S2 victim** | **KT Corporation** AS4766 — 집 KT 인터넷 |
| `101.x`  | **S2 attacker** | **Public WiFi / Cafe** — SK BB 류 공용망 (탈취 토큰 사용처) |
| `203.0.113` / `198.51.100` / `192.0.2` / `45.32.x` (옥텟 100~254) | **S5** 풀 | **Mixed Hosting / VPS** — Vultr + 시뮬용 placeholder |

> 단일 IP 시나리오는 마지막 옥텟 **1~99** (50/77/40/66), S5 풀은 **100~254** 로 강제 분리되어 충돌 0.

---

## 🔀 3. 시나리오 상세

### S2 — JWT 토큰 하이재킹 (`scenarios/s2_token_hijack.py`)

**시나리오 서사**: 사용자가 정상 KT 가정 인터넷에서 `/auth/login` 으로 로그인 → auth-server 가 ES256 + KMS 서명으로 **진짜 access token** 발급. 그 토큰이 (XSS / MITM / 토큰 저장소 탈취 등으로) 공격자에게 넘어가, 카페·공용망에서 같은 토큰으로 민감 정보를 burst 조회.

> **다른 시나리오와의 차이**: `forge_token` 사용 X. **auth-server 가 진짜 발급한 토큰** 을 그대로 사용. 서명·jti·iat 모두 운영 발급치와 동일하며, 차이는 **source IP 뿐**. "키 자체를 탈취해 임의 sub 로 위조하는" S4 와는 공격 벡터가 명확히 분리.

| 항목 | 값 |
|------|---|
| victim 계정 | `.env` 의 `VICTIM_EMAIL` / `VICTIM_PASSWORD` (운영 RDS 실계정) |
| 토큰 획득 | `POST {ZETI_ALB_URL}/auth/login`, **XFF = victim IP** |
| **1단계 — Victim 정상** | XFF `222.110.15.50` (KT) · 15~45s 간격 · 5분 |
| **2단계 — Attacker burst** | XFF `101.235.1.77` (Cafe) · 2~5s 간격 · 8건 |

**기대 탐지 신호**:
- `token_replay`: 동일 jti 가 5분 내 서로 다른 IP/ASN 에서 관측 → raw 100
- 회선 점프 (KT → Cafe) → ip_class 교차 base 35 + fan-out 가중
- `response_sensitivity` `/api/addresses` 결합 → final ≥ 90

```bash
python scenarios/s2_token_hijack.py --victim-minutes 5 --burst 8
```

### S4 — 서명키 탈취 + 즉시 Enumeration (`scenarios/s4_enumeration.py`)

**시나리오 서사**: 공격자가 KMS 외부 alias 키를 탈취해 **AWS Seoul EC2** 에서 victim 풀을 순차로 긁어내려는 "고전적 enumeration".

| 항목 | 값 |
|------|---|
| source IP | `15.164.10.40` (AWS Seoul AS16509) 단일 |
| endpoint | `/api/addresses/{sub}` 단일 |
| 토큰 | `forge_token(sub, ttl=600)` — 매 호출 새 jti |
| 페이스 | 1.0 RPS = 분당 60 건 |
| 풀 | `get_sequential_pool()` — `VICTIM_SUB_START` 부터 순차 |

**기대 탐지**: t=05:00 `ip_user_diversity` override 100 → Slack 즉시 / t=05:30 Haiku 인시던트 리포트.

```bash
python scenarios/s4_enumeration.py --duration 15 --rps 1.0
```

### S5 / S5b — 분산 Enumeration (두 변종)

쿠팡 사고 (2,300 IP × 3,367 계정, **IP:계정 ≈ 0.68:1**) 의 IP 분포를 비례 축소. 호출 방식 자체는 S4 와 통일 (각 사용자 1회, `VICTIM_COUNT` 건, 1초 간격) — 공격자의 **회피 수준** 만 두 변종으로 분리.

| 변종 | sub 선택 | 회피하지 못하는 신호 |
|------|---------|--------------------|
| **S5** (어설픈) | START 부터 순차 | **풀 합산 sub 단조 패턴** (글로벌 시퀀스 / Route B ASN 다양성) |
| **S5b** (분산 botnet) | 랜덤 비복원 추출 | `F-FirstSeen-Sensitive` 등 보완 factor |

```bash
python scenarios/s5_distributed.py --duration 30
python scenarios/s5b_distributed_random.py --duration 30
```

### S6 — Slow & Low + Impossible Travel (`scenarios/s6_slow_low.py`)

**시나리오 서사**: 쿠팡 7개월 미탐지 재현 + 지리적 이상 징후. 단일 미국 가정용 IP에서 분당 1~2 건 천천히 긁어, 5분 윈도우 z-score 는 미달시키되 — 한국 사용자 풀 (`140000xxx`) 을 **해외 IP 로 조회** 하는 패턴이 누적되어 Impossible Travel 유발.

| 항목 | 값 |
|------|---|
| source IP | `98.138.10.66` (US Residential) 단일 |
| 페이스 | 30~60s sleep (분당 1~2 건) |
| 풀 | `get_shuffled_pool(seed=42)` 랜덤 비복원 |

**기대 탐지 타임라인**:
- 첫 1h: 5분 윈도우 미달 → 모든 신호 0점 (의도된 사각지대)
- t=01:00: 1h 윈도우 의심 단계 (70)
- t=24:00: **`cumulative_exfil` 24h 윈도우 z 폭증 + Impossible Travel** → 100

```bash
python scenarios/s6_slow_low.py --duration 6 --min-interval 30 --max-interval 60
```

### S8 — 비정상 장수명 토큰 (`scenarios/s8_expired_token.py`)

**시나리오 서사**: 키를 탈취한 공격자가 매번 재위조하는 churn 을 줄이려 **TTL 을 비정상적으로 길게** (기본 7200s = 2h) 발급. S4 처럼 폭 신호 (`ip_user_diversity`) 를 피하려 victim 수는 작게.

| 항목 | 값 |
|------|---|
| source IP | 단일 |
| endpoint | `/api/addresses/{sub}` |
| 토큰 | `forge_token(sub, ttl=7200)` — **장수명 (정상 600s 의 12배)** |
| 폭 신호 | 없음 (victim 적음) |

**기대 탐지**: `token_violation` 룰 — T007 (exp-iat > 3600) = 80 / T002 (exp-iat > 1800) = 70. 결정론 팩터 단독으로 final 80 → 알람. `attacker_level = L2`.

> 음수 TTL 주면 만료 토큰 → T001 (exp < now) = 80.

```bash
python scenarios/s8_expired_token.py --token-ttl 7200
python scenarios/s8_expired_token.py --token-ttl -300    # 이미 만료된 토큰
```

---

## 📦 4. 디렉토리 구조

```
attack-simulation/
├── .env.example                # 환경변수 템플릿
├── requirements.txt
├── run.sh                      # 발표 시연 일괄 (S4 + S6)
├── demo_s2.py                  # 🎬 S2 단독 시연 (시나리오 + SSM trigger)
├── demo_s5.py                  # 🎬 S5 단독 시연 (시나리오 + SSM trigger)
├── SCENARIOS.md                # 시나리오별 행위 / 타임라인 상세
│
├── leaked-key/                 # 🔑 탈취 가정 ES256 개인키 (★ Git 금지)
│   ├── pkcs8_private_key.pem
│   ├── pkcs8_private_key.der   # KMS BYOK import 용
│   └── README.md
│
├── lib/                        # 공통 모듈
│   ├── http_client.py          # XFF 위조 + 재시도 wrapper
│   ├── ip_pool.py              # 분산 IP 풀 (S5)
│   ├── target_pool.py          # victim sub 풀 (순차/랜덤, VICTIM_COUNT)
│   ├── token_forge.py          # JWT ES256 위조 (forge_token)
│   ├── token_utils.py          # 디코더 / 검증 helper
│   └── result_writer.py        # results/*.jsonl 기록
│
├── scenarios/                  # 6 시나리오 (각각 단독 실행)
│   ├── s2_token_hijack.py
│   ├── s4_enumeration.py
│   ├── s5_distributed.py
│   ├── s5b_distributed_random.py
│   ├── s6_slow_low.py
│   └── s8_expired_token.py
│
└── results/                    # 실행 산출물 (jsonl + log, gitignore)
    └── s{N}_{date}.jsonl
```

---

## ⚙️ 5. 환경변수 (.env)

| 변수 | 의미 |
|------|------|
| `ZETI_ALB_URL` | 공격 대상 ALB DNS (모든 시나리오 공통) |
| `LEAKED_KEY_PATH` | **S4/S5/S6/S8** 위조 서명 개인키 경로 (S2 는 무관) |
| `KID` | KMS alias (위조 서명 헤더 `kid` 로 박힘) |
| `VICTIM_SUB_START` / `VICTIM_SUB_END` | 접근 가능한 사용자 id 범위 (기본 140000002~140000500 → 498명) |
| `VICTIM_COUNT` | 위 범위에서 공격할 사용자 수. 비우면 풀 전체 |
| `VICTIM_EMAIL` / `VICTIM_PASSWORD` | **S2 전용**, 운영 RDS 실계정 |
| `S4_SOURCE_IP` 외 | 시나리오별 XFF 위조용 source IP |
| `S5_IP_POOL_SIZE` | S5/S5b 분산 IP 풀 크기 (0 이면 `victim_count × 0.68` 자동) |

---

## 🛠️ 6. Tech Stack

| Category | Stack | 비고 |
|----------|-------|------|
| **Language** | Python 3.11+ | requests + dotenv |
| **암호** | `cryptography` ECDSA SHA-256 | ES256 위조 (DER → R+S 변환) |
| **HTTP** | `requests` + 재시도 + 백오프 | XFF 위조 wrapper |
| **결과 저장** | jsonl (`results/`) | 시나리오별 시간 stamped |
| **시연 자동화** | `subprocess` + AWS SSM | `aws ssm send-command` 로 UBA EC2 cron trigger |
| **CI/CD** | GitHub Actions | push 시 syntax + smoke 검증 (배포 없음) |

---

## 🧭 7. Why → How → Impact → Deliverable

### 1️⃣ Why — UBA 가 "진짜 위협" 을 못 잡으면 의미 없다

| 문제 | UBA 가 검증되지 않은 상태에서의 위험 |
|------|---------------------------------|
| 룰만 보고 잡힌다고 자평 | 실제 분산 공격은 다 빠져나감 |
| 합성 트래픽 없음 | KPI (MTTD / TPR / FPR) 측정 불가 |
| 쿠팡 같은 저속 7개월 시나리오 재현 어려움 | 멘토 스토리라인의 _그_ 부분 못 보여줌 |
| 회피 수준별 변종 없음 | UBA 의 _보완 factor_ 필요성 입증 못 함 |

### 2️⃣ How — 회피 수준별 시나리오 매트릭스

본 시뮬은 **공격자의 회피 수준** 을 의도적으로 단계화:

| 수준 | 시나리오 | 회피 기술 | 어떤 factor 가 잡는가 |
|------|---------|----------|---------------------|
| 0 (어설픔) | **S4** | 회피 없음, 단일 IP | `ip_user_diversity` override |
| 1 (IP만 가림) | **S5** | IP 분산, sub 순차 | 글로벌 sub 시퀀스 + Route B ASN |
| 2 (완전 분산) | **S5b** | IP + sub 모두 random | 보완 factor (`F-FirstSeen-Sensitive`) |
| 3 (시간 회피) | **S6** | 분당 1~2 건 + 해외 IP | `cumulative_exfil` 24h + Impossible Travel |
| 4 (정상 페이스 + 토큰 변형) | **S8** | 장수명 토큰 | `token_violation` T007 |
| ★ (탈취 토큰) | **S2** | 위조 X, 진짜 토큰 + 회선 점프 | `token_replay` |

### 3️⃣ Impact — UBA KPI 측정의 기반

본 시뮬이 발사한 트래픽이 **UBA `docs/kpi/` 의 모든 측정치의 원천**:

| KPI 측정 | 사용 시나리오 |
|---------|--------------|
| **MTTD (S4)** 5~15분 | S4 1.0 RPS × 100 sub |
| **MTTD (S6)** 6~24h | S6 6h × 분당 1~2 건 |
| **TPR (6 시나리오)** | S2/S4/S5/S5b/S6/S8 통제 발사 |
| **FPR (v1/v2 baseline)** | AMBIG_NAT 코호트 (uba-analyzer 측 별도 합성) |

### 4️⃣ Deliverable — 단독 실행 + 시연 자동화

| 산출물 | 형식 | 활용 |
|--------|------|-----|
| **시나리오 단독 실행** | `python scenarios/s{N}_*.py --duration N` | 검증/디버그 |
| **시연 자동화** (`demo_s2.py` / `demo_s5.py`) | `python demo_*.py` 1 줄 | 발표 영상용 |
| **일괄 시연** (`run.sh`) | `./run.sh demo` / `full` | S4 + S6 병렬 |
| **`results/*.jsonl`** | 요청별 응답·timing | UBA TPR / MTTD 계산 입력 |

---

## 🚀 8. Getting Started

### Prerequisites

- Python 3.11+
- ZETI 자체 인프라 ALB DNS 접근권
- AWS CLI + SSM Session 권한 (demo_*.py 용)
- ES256 개인키 (`leaked-key/pkcs8_private_key.pem`) — 시뮬 전용, **Git 금지**

### 셋업

```bash
git clone https://github.com/ZETTY-ZEROTRUST/attack-simulation.git
cd attack-simulation
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env 편집: ZETI_ALB_URL, LEAKED_KEY_PATH, VICTIM_EMAIL/PASSWORD, 풀 범위 등

# leaked-key/README.md 따라 ES256 개인키 생성 (시뮬 전용)
```

### 단일 시나리오 실행

```bash
python scenarios/s2_token_hijack.py --victim-minutes 5 --burst 8
python scenarios/s4_enumeration.py --duration 15 --rps 1.0
python scenarios/s5_distributed.py --duration 30
python scenarios/s5b_distributed_random.py --duration 30
python scenarios/s6_slow_low.py --duration 6 --min-interval 30 --max-interval 60
python scenarios/s8_expired_token.py --token-ttl 7200
```

### 시연 자동화 (Slack pop 까지 자동)

```bash
python demo_s2.py    # S2 + SSM trigger → ~5분 후 Slack
python demo_s5.py    # S5 + SSM trigger → ~5분 후 Slack
```

### 일괄 (run.sh)

```bash
./run.sh demo      # S4 15분 + S6 6h 압축 (병렬)
./run.sh full      # S4 30분 + S6 24h
./run.sh s4-only   # S4 단독
./run.sh s6-only   # S6 단독
```

---

## 🔗 9. 관련 레포 (ZETTY Org)

| 레포 | 본 attack-simulation 과의 관계 |
|------|-------------------------------|
| [`backend`](https://github.com/ZETTY-ZEROTRUST/backend) | 의도된 4 취약점 + IDOR endpoint 들 — **공격 대상** |
| [`log-pipeline`](https://github.com/ZETTY-ZEROTRUST/log-pipeline) | XFF 위조 트래픽을 `asn-classify` 가 ip_class 분류 — **분류 검증** |
| [`uba-analyzer`](https://github.com/ZETTY-ZEROTRUST/uba-analyzer) | 7 factor + LLM 으로 본 시뮬 트래픽 잡아냄 — **탐지 검증** |
| [`.github`](https://github.com/ZETTY-ZEROTRUST/.github) | Org Overview README |

---

## 📋 10. 안전 / 윤리

### 절대 규칙

- ❌ **자기 소유 ZETI 테스트 인프라 외에서 실행 금지** — 본 시뮬은 인증된 모의 침투 / 자체 검증 용도만
- ❌ **`leaked-key/*.pem` `*.der` Git 커밋 금지** (`.gitignore` 확인)
- ❌ **시뮬 종료 후 키 보안 삭제** (`shred -u` / `sdelete`)
- ❌ **실제 사용자 credential 노출 금지** — `VICTIM_EMAIL/PASSWORD` 는 운영 RDS 의 테스트용 계정만

### 컴플라이언스 매핑

| 표준 | 본 레포의 충족 방식 |
|------|---------------------|
| **MITRE ATT&CK T1078 (Valid Accounts)** | S2 토큰 하이재킹 시연 |
| **MITRE ATT&CK T1199 (Trusted Relationship)** | S5/S5b 분산 IP 풀 |
| **MITRE ATT&CK T1110.004 (Credential Stuffing)** | S4/S5 sub enumeration |
| **MITRE ATT&CK T1078.004 (Cloud Accounts)** | S6 Impossible Travel |
| **OWASP A01 Broken Access Control** | IDOR endpoint 표적 |
| **OWASP A02 Cryptographic Failures** | ES256 키 탈취 시나리오 (S4/S5/S6/S8) |

---

## 🤝 11. 기여 가이드

### 절대 규칙 (DO NOT)

- ❌ **운영 인프라 (자체 ZETI 아님) 공격 시뮬 금지**
- ❌ **새 시나리오 추가 시 IP 색깔 매트릭스 충돌 금지** — 단일 IP 시나리오는 옥텟 1~99, 분산 풀은 100~254
- ❌ **`forge_token` 이 ES256 외 알고리즘 (HS256 등) 사용 금지** — backend KMS 와 일치 필요
- ❌ **시연 자동화 (demo_*.py) 에서 throttle 우회 외 다른 cron 영향 금지**

### 커밋 컨벤션

- 포맷: `<type>(<scope>): <한글 제목>`
- scope: `attack-sim` (시나리오/lib) / `demo` (demo_*.py) / `ci`
- 예: `feat(attack-sim): S8 비정상 장수명 토큰 시나리오 추가`

---

> **본 attack-simulation 은 ZETI 의 _검증 트래픽 원천_ 입니다.**
> 6 시나리오 × 회피 수준 매트릭스 × XFF 위조 + IP 색깔 — UBA 의 모든 factor 가 실제로 작동하는지 _데이터_ 로 입증합니다.
> "쿠팡 사고 재현이 핵심 요구사항" — 그 _재현_ 의 실체.
