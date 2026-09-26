# S-02 탈취 토큰 지속 사용 — RT 회전·재사용 감지·폐기 + 매 요청 상태 확인

- 상태: 완료
- 연결: 로드맵 S2 · 부하 L-4(`load/results/l4_state_check.json`)
- 작성/갱신: 2026-09-27

## S — 공격

탈취한 토큰을 계속 쓰는 상황을 재현한다(`scenarios/v2/s2_token_reuse.py`).
1. 정상 회전 후 **구 RT 재사용**(토큰이 복제·탈취된 정황).
2. 로그아웃 이후에도 **기존 AT로 보호 API 계속 호출**.

## T — 왜 막나

서명이 유효해도 탈취된 토큰이 무기한 통용되면 안 된다. 회수(로그아웃·비번 변경·권한 회수)가 다음 보호 요청부터 반영돼야 한다. 기준: 구 RT 재사용은 family 폐기, 로그아웃 후 기존 AT는 401.

## A — 방어와 근거

### 웹 근거 (표준)
- **RFC 9700 §4.14.2**: 공개 클라이언트 RT는 매 사용 시 회전하고 재사용(replay) 감지 시 **grant의 token family 전체를 폐기**해야 한다. "회전 후 폐기 규칙"이야말로 회전을 실제 탐지 신호로 만든다. [RFC 9700 요약(Django OAuth Toolkit)](https://django-oauth-toolkit.readthedocs.io/en/3.4.0/security.html), [Auth0 rotation/reuse detection](https://dev.to/mukesh_13/refresh-token-rotation-under-the-hood-how-auth0-catches-a-stolen-token-before-its-ever-replayed-3n1l)
- AT 회수 반영: 상태를 원본(DB)에서 확인. 초기엔 positive cache를 두지 않는다(회수 정확성 우선).

### 구현
- RT는 원문 대신 **SHA-256 해시**만 저장. family_id + generation으로 계보 관리.
- `/auth/refresh`: ACTIVE면 소비(CONSUMED)하고 같은 family의 다음 세대 발급. **CONSUMED/REVOKED 재제시 → family 전체 REVOKED** → 401.
- `/auth/logout`: `users.auth_version` 증가 + 사용자 RT family 전부 폐기.
- **API 매 요청**: AT의 `authv` 클레임과 `users.auth_version`(PK 조회)을 대조. 불일치 → 401. positive cache 없음.

### 대안 비교
| 선택지 | 트레이드오프 | 결정 |
|---|---|---|
| RT 회전 없음(장수 RT) | 탈취 시 무기한 사용 | 제외 |
| 회전만, family 폐기 없음 | 재사용을 탐지 신호로 못 씀(RFC 9700이 지적) | 제외 |
| 회전 + family 폐기 | 표준 | **채택** |
| AT 회수: 매 요청 DB 확인 | 회수 즉시 반영, 요청당 조회 비용 | **채택(초기)** — PK 조회라 비용 작음 |
| AT 회수: Redis positive cache | 처리량↑, 회수 반영 지연·stale 위험 | 후속(ADR 필요), L-4 개선안 |

### 시행착오 (실측으로 잡은 함정)
- 재사용 시 family 폐기가 반영 안 됨 → 원인: `AuthService.refresh`가 `@Transactional`이라 폐기 후 **예외 롤백으로 폐기가 취소**. → refresh의 트랜잭션 경계 제거(폐기는 rotate가 커밋).
- 로그아웃해도 authVersion이 안 올라감 → 원인: `@Modifying(clearAutomatically)`가 **flush 전에 컨텍스트를 비워** authVersion dirty 상태 유실. → `flushAutomatically=true` 추가.
- JPQL enum을 문자열 리터럴로 비교해 0행 갱신 → enum 경로 리터럴로 수정.

## R — 재공격 결과

`scenarios/v2/s2_result.json`:

| 검사 | 결과 |
|---|---|
| 정상 회전 | 200 |
| 구 RT 재사용 | 401 |
| 재사용 후 최신 RT(같은 family) | 401 (family 폐기) |
| 로그아웃 전 /users/me | 200 |
| 로그아웃 후 기존 AT /users/me | 401 |
| 로그아웃 후 RT refresh | 401 |

### 부하 L-4 (매 요청 authVersion 확인 비용)

`load/results/l4_state_check.json` — VU당 토큰 재사용, /users/me 반복(로그인 배제):

| 지표 | 값 |
|---|---|
| /users/me p95 | 22.9ms |
| 처리량 | 226 req/s (VU 75, 0.2s think time) |
| 실패 | 0% |

해석: authVersion 확인은 PK 점조회라 요청당 오버헤드가 한 자릿수 ms. 회수 정확성을 위해 DB 확인을 유지한다. 처리량이 병목이 되면 Redis positive cache(반영 지연·stale 허용 명시한 ADR 필요)를 도입해 재측정한다.

## 자소서 한 줄 (초안)

탈취한 refresh token 재사용과 로그아웃 후 토큰 지속 사용 공격을 재현하고, RFC 9700에 따른 회전+재사용 시 토큰 패밀리 전체 폐기와 매 요청 상태(authVersion) 확인으로 차단했습니다. 구현 중 트랜잭션 롤백으로 폐기가 취소되던 결함을 부하·시나리오 실행으로 발견해 트랜잭션 경계와 flush 시점을 바로잡았습니다.
