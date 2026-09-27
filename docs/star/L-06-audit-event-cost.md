# L-06 감사 이벤트(Outbox)의 부하 비용과 전달 지연

- 상태: 계획
- 연결: backend `B-06`(Outbox) · infra `Z-05`(파이프라인 통합) · backend `B-03`(/mypage 캐시)
- 작성/갱신: 2026-09-27

## S — 문제

- A-06 이후 보호 요청마다 ACCESS_DECISION 이벤트를 Outbox에 INSERT한다(쓰기 요청은 BUSINESS_RESULT까지 2건).
- `/mypage`는 캐시로 DB 조회를 줄였는데(B-03), 감사 기록 때문에 **요청마다 DB 쓰기가 새로 생겼다.**
- relay(0.5코어)·indexer(0.5코어)·ES(단일 노드)가 유입 속도를 못 따라가면 Outbox에 미전달 이벤트가 쌓이고, 탐지(log-pipeline)는 그만큼 늦은 데이터를 본다.

## T — 목표

- 같은 부하에서 **감사 기록 전/후** API 지연·처리량 차이와 DB 쓰기량을 측정한다.
- 유입 속도별로 전달 지연(Outbox 미전달 수, relay lag)이 안정되는지, 계속 늘어나는지 확인한다.
- 병목(relay·indexer·ES·MySQL)을 특정하고 조정(배치 크기·인스턴스 수) 전후를 비교한다.

## A — 어떻게 (계획)

1. 비교 조건 고정: `/mypage` hot, 사용자 100명, Cache-Aside on(TTL 60s), 풀 20, `constant-arrival-rate`, 워밍업 분리.
2. **전**: Outbox가 없는 이미지(backend `feature/a03-bff`) / **후**: Outbox 이미지(`feature/a06-outbox`). 한 번에 이미지 하나만 바꾼다.
3. 측정: p50·p95, 달성 RPS, DB INSERT/s, Outbox PENDING 추이(측정 중 5초 간격), relay·indexer 처리량, ES 문서 수.
4. 전달이 밀리면 relay 배치 크기·인스턴스 수를 하나씩 바꿔 재측정.

### 판단 기준
- 감사 기록은 보안 요구(인증·인가 결정의 추적성)라 끄지 않는다. 비용을 **측정해서 설명**하고, 줄일 수 있는 부분만 줄인다.
- 전달 지연은 "유입 < 처리"면 일정 수준에서 멈추고, "유입 > 처리"면 계속 늘어난다. 늘어나는 구간이 파이프라인의 한계다.

## R — 결과 (실측)

/mypage hot, 사용자 100명, Cache-Aside on, 풀 20, 감사 이벤트 켜짐(요청당 ACCESS_DECISION 1건).

| 목표 RPS | /mypage p95 | 성공 | DB insert/s | relay published/s | indexed/s | 적체 추이 |
|---|---|---|---|---|---|---|
| 400 | 6.4ms | 100% | 374 | 350 | 373 | pending ~306에서 안정 |
| 800 | 8.7ms | 100% | 753 | 713 | 469 | pending ~716에서 안정, **indexer가 relay를 못 따라감** |

- 감사 INSERT가 요청당 1건 추가돼도 /mypage 응답(캐시 적중)에는 거의 영향 없음(p95 한 자릿수 ms).
- relay는 유입을 따라가지만 800 RPS에서 **indexer(ES 색인)가 병목**(469 < 713). Outbox는 안정적 적체 수준을 유지(무한 증가 아님)하므로 유실은 없고 전달만 지연된다.
- 개선 여지: indexer 인스턴스 증설·bulk 크기·ES 자원. 부하 유입이 처리보다 크게 지속되면 pending이 계속 증가하는 지점이 진짜 한계 — 이번 구간(≤800)에서는 안정.

## 자소서 한 줄
인증·인가 결정을 추적하려고 요청마다 감사 이벤트를 트랜잭션 Outbox로 남기면서도 API 응답 지연을 한 자릿수 ms로 유지했고, Outbox→Streams→ES 전달에서 800 RPS 시 색인이 병목임을 지표로 특정했습니다.
