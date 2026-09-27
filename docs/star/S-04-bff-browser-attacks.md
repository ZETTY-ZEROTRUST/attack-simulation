# S-04 B0(BFF) 브라우저 공격 — 토큰 탈취·CSRF·세션 고정·프록시 우회

- 상태: 완료
- 연결: 로드맵 B0(BFF) · backend `docs/star/B-04-bff-step1.md`
- 작성/갱신: 2026-09-27

## S — 문제 (Before)

- 기존 `/auth/login`은 **AT와 RT 원문을 응답 본문으로 클라이언트에 준다.** 브라우저가 이 응답을 받으면 JS가 읽을 수 있는 위치(메모리·storage)에 토큰이 놓인다.
- 이 상태에서 XSS가 하나라도 나면 토큰을 외부로 보낼 수 있고, RT까지 가져가면 공격자가 브라우저 밖에서 계속 갱신하며 쓴다(S2의 전제).

## T — 목표

- 브라우저에 **어떤 응답으로도 AT·RT가 도달하지 않는다.**
- 쿠키 기반이 되면서 새로 생기는 위험(CSRF, 세션 고정, 쿠키 재사용, 프록시 우회)을 각각 막는다.
- 성공 기준(After):
  - `/bff/login`·`/bff/session` 응답에 토큰 문자열 0건, 세션 쿠키는 `__Host-`·HttpOnly·Secure·SameSite
  - 다른 Origin의 상태 변경·로그인, CSRF 토큰 없는 상태 변경 → 403
  - 로그인 전에 심은 세션 ID는 로그인 후 쓸 수 없음(새 ID 발급)
  - 로그아웃 후 같은 쿠키 → 401
  - 허용 목록 밖·경로 우회·절대 URL → 404(또는 400)
  - 다른 사용자의 AT를 Authorization 헤더로 끼워 넣어도 무시되고 쿠키 주인의 데이터만 반환

## A — 어떻게

### 계획
- 러너 `scenarios/v2/b0_bff_browser.py`(표준 라이브러리만, 로컬 secure 대상만). Before는 `/auth/login` 응답 노출 여부만 확인한다(토큰 원문은 결과에 기록하지 않고 존재 여부만).
- 결과는 `scenarios/v2/b0_bff_result.json`, 판정은 기대 코드와 비교.

### 대안 비교 (웹 토큰 보관 방식)
| 방식 | XSS 시 | 새 위험 | 판단 |
|---|---|---|---|
| AT·RT를 JS 메모리/storage | 토큰 원문 탈취 가능 | — | 제외 |
| AT 메모리 + RT HttpOnly 쿠키 | AT 탈취 가능, RT는 못 읽음 | refresh CSRF, 멀티탭 경합 | 비교 대안 |
| **BFF(서버 vault, 브라우저엔 세션 쿠키만)** | 토큰 원문 없음 | CSRF·세션 고정·세션 탈취 → 쿠키 속성·CSRF·Origin·세션 교체로 방어 | **채택** |

### 한계 (정직하게 남길 것)
- BFF는 **XSS가 사용자 권한으로 요청을 보내는 것(session riding)까지 막지는 못한다.** 막는 것은 "토큰을 가져가서 브라우저 밖에서 계속 쓰는 것"이다. XSS 자체는 CSP·출력 인코딩으로 막아야 한다.
- 네트워크·단말 악성코드로 쿠키가 통째로 탈취되면 세션이 살아있는 동안은 쓸 수 있다 → 로그아웃·회수(S2)와 행위 탐지(S4) 범위.

## R — 결과

`scenarios/v2/b0_bff_result.json` (nginx HTTPS 경유, 2026-09-27)

| 공격 | 대상 | 결과 | 막은 곳 |
|---|---|---|---|
| **Before**: 기존 로그인 응답의 토큰 노출 | `POST /auth/login` | **AT·RT 원문 노출됨** | — (문제 확인) |
| XSS 토큰 탈취(응답에서 토큰 찾기) | `POST /bff/login`, `GET /bff/session` | 토큰 문자열 0건 | BFF가 토큰을 서버 vault에만 보관 |
| 쿠키 탈취 가능성 | 세션 쿠키 속성 | `__Host-`, HttpOnly, Secure, SameSite, Path, Domain 없음 | 쿠키 속성(JS에서 읽기 불가) |
| CSRF: 토큰 없음 / 다른 Origin / 정상 | `PUT /bff/api/users/me` | 403 / 403 / 200 | CSRF 토큰 + Origin 정확 일치 |
| 로그인 CSRF(다른 Origin) | `POST /bff/login` | 403 | Origin 정확 일치 |
| 세션 고정(로그인 전 심은 ID로 접근) | `GET /bff/api/users/me` | 401 | 로그인 시 세션 새로 발급 |
| 다른 사용자 AT를 Authorization에 끼워 넣기 | `GET /bff/api/users/me` | 200이지만 **쿠키 주인(user001) 데이터** 반환 | 브라우저 Authorization 제거 후 vault AT 부착 |
| 허용 목록 밖 경로 | `/bff/api/lab/forge`, `/bff/api/actuator/...` | 404 | BFF allowlist |
| 인코딩 경로 우회 `..%2f` | `/bff/api/..%2f..%2fauth/login` | 400 | Tomcat(인코딩 슬래시 거부) |
| `../` 우회 · 절대 URL | `/bff/api/users/../../auth/login`, `/bff/api/http://evil.example/` | 400 | Spring Security StrictHttpFirewall |
| 로그아웃 후 탈취 쿠키 재사용 | 같은 세션 쿠키 | 401 (로그아웃 응답 `Zetty-Server-Revocation: confirmed`) | 세션·vault 폐기 + 서버 토큰 회수 |

판정 9/9 통과. 여러 계층(Tomcat → Spring 방화벽 → BFF allowlist)이 겹쳐 프록시 우회를 막는다.

### 남은 위험 (범위 밖으로 명시)
- XSS가 **사용자 권한으로 요청을 보내는 것**(session riding)은 막지 못한다. 토큰을 가져가 브라우저 밖에서 쓰는 것을 막은 것이다 → CSP·출력 인코딩 필요.
- 쿠키가 단말·네트워크에서 통째로 탈취되면 세션이 살아있는 동안 유효 → 회수(S2)·행위 탐지(S4)로 다룬다.

## 자소서 한 줄 (초안)
로그인 응답으로 토큰 원문이 브라우저에 전달되던 구조를 BFF로 바꿔 토큰을 서버 암호화 금고에만 두고, 쿠키 전환으로 새로 생기는 CSRF·세션 고정·프록시 우회·탈취 쿠키 재사용 공격 9종을 재현해 모두 차단됨을 확인했습니다.
