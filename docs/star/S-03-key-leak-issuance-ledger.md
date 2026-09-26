# S-03 서명키 유출로 토큰 위조 — 발급 대장 + 주체 대조

- 상태: 완료
- 연결: 로드맵 S3 · 위협: 개인키(Sign 권한) 유출, 발급 DB 쓰기 권한은 없음
- 작성/갱신: 2026-09-27

## S — 공격

공격자가 KMS Sign 권한을 얻어(lab `auth-lab`, profile lab로 재현) **실제 서명키로 유효 서명**된 토큰을 만든다. 발급 대장에는 쓸 수 없다.
- 새 jti 위조 / 실제 jti 복사 + sub 변경 재서명 / 유령 주체 위조.
- run: `scenarios/v2/s3_key_leak.py`, 결과 `scenarios/v2/s3_result.json`.
- lab 위조기는 `@Profile("lab")`이라 secure 기본 스택에는 없다(secure에서 `/lab/forge` = 401, 핸들러 없음).

## T — 왜 막나

서명·kid가 유효하다고 발급을 보장하지 않는다(키 유출 시). 서명 검증만으로는 위조를 막을 수 없으므로, **실제로 발급한 토큰인지**를 별도 원본과 대조해야 한다. 기준: 정상 토큰 200, 위조(대장 미기록/불일치) 401.

## A — 방어와 근거

### 웹 근거
- jku/x5u 임의 URL 금지, **로컬 JWKS·신뢰 kid allowlist**만 사용. [PortSwigger JWT](https://portswigger.net/web-security/jwt), [Curity JWT best practices](https://curity.io/resources/learn/jwt-best-practices/)
- 서명 검증을 넘어선 소유/발급 증명: sender-constrained(DPoP, RFC 9449)와 발급 상태 확인. 본 프로젝트는 **발급 대장(digest 대조)** 을 택하고 DPoP는 후속 후보로 남긴다. [RFC 9449 DPoP](https://datatracker.ietf.org/doc/html/rfc9449)

### 구현
- 발급 시 Auth가 `token_ledger`에 **정확히 발급한 compact JWT의 SHA-256 digest** + jti·sub·kid·status·만료를 기록(원문 토큰은 저장 안 함). 등록은 발급과 같은 트랜잭션.
- API 매 요청: 서명·authVersion 통과 후, 제시된 compact 토큰의 digest를 계산해 jti로 대장을 찾고 **digest 일치 + ACTIVE + sub 일치**를 확인. 하나라도 어긋나면 401.
- kid는 로컬 JWKS(신뢰 kid)만. 토큰의 jku/x5u는 따르지 않는다.

### 대안 비교
| 방식 | 판단 |
|---|---|
| 서명 검증만 | 키 유출 시 위조 무력화 불가 | 
| jti 존재만 확인 | 기존 jti 복사·재서명을 못 막음(digest가 다름을 안 봄) → 불충분 |
| **발급 digest 대장 대조** | 위조(미발급)·변조(digest 불일치) 차단 | **채택** |
| DPoP(sender-constrained) | 소유 증명까지. 클라이언트 키 관리 필요 | 후속 후보 |
| opaque token + introspection | 매번 원본 조회. JWT 이점 포기 | 비교 대상 |

한계: Auth/DB까지 장악되면 이 통제는 보장하지 않는다(정상 발급 토큰 탈취는 S2/S4 범위).

## R — 재공격 결과

`scenarios/v2/s3_result.json`:

| 검사 | 결과 |
|---|---|
| 정상 발급 토큰 | 200 |
| 새 jti 위조(유효 서명) | 401 |
| 실제 jti 복사 + sub 변경 재서명 | 401 |
| 유령 주체 위조 | 401 |

## 자소서 한 줄 (초안)

서명키가 유출돼 진짜 키로 서명된 위조 토큰이 만들어지는 상황을 lab에서 재현하고, 발급 시 기록한 토큰 digest 대장과 매 요청 대조해(서명 검증을 넘어) 미발급·변조 토큰을 전부 차단했습니다. jti 존재 확인만으로는 기존 토큰 재서명을 못 막는다는 점을 근거로 digest 대조를 선택했습니다.
