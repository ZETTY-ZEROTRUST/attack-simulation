# S-01 BOLA(객체 단위 인가) — 남의 주문·주소 접근 차단

- 상태: 완료
- 연결: 로드맵 S1 · 부하 L-2(`backend/docs/star/B-02`)
- 작성/갱신: 2026-09-27

## S — 공격

정상 로그인한 user001이 요청의 객체 ID만 바꿔 user002의 주문 상세·주소를 노린다.
- 피해자 토큰으로 실제 소유 주문 ID를 얻은 뒤, 공격자 토큰으로 `/orders/{id}/detail` 호출.
- 순차 주소 ID로 `PUT /addresses/{id}` 시도.
- run: `scenarios/v2/s1_bola.py`, 결과 `scenarios/v2/s1_result.json`.

## T — 왜 막나

금융 서비스에서 주문·주소·현관 비밀번호는 타인이 ID만 알면 조회·수정돼선 안 된다(OWASP API1 BOLA). RBAC 통과(로그인한 사용자)만으로 객체 접근을 허용하면 안 된다. 기준: 타인 소유·부재는 동일하게 404(존재 은닉), 본인 자원만 성공.

## A — 방어와 근거

### 현재 방어 (이미 적용된 소유권 쿼리)
- 모든 업무 조회/수정이 `@AuthenticationPrincipal userId`를 **repository 쿼리 조건**에 넣는다: `findByOrderIdAndUserId`, `findByAddressIdAndUserId`, `findByUserId`. RBAC가 아니라 소유권으로 막는다.
- 공개 ID 불투명성에 기대지 않는다(순차 정수 ID여도 소유권으로 차단).

### 웹 근거
- BOLA는 API 보안 1위 위협. 인가를 **객체 수준에서, 데이터 계층까지** 내려야 한다. [OWASP API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- 존재 여부 노출을 막기 위해 타인 소유와 부재를 같은 404로 둔다(403은 리소스 존재를 알려줌).

### 부하 테스트 중 발견한 결함 → 개선 (최소 권한 과잉)
- S1 실행 중 **본인 주소 수정이 500**. 원인: `api_app` MySQL 계정에 UPDATE 권한이 없어(초기엔 SELECT만) 정상 쓰기가 실패. 교차 사용자는 소유권 쿼리로 이미 404라 보안 문제는 아니지만, **정상 업무가 깨지는 안정성 결함**.
- 개선: 직무 분리를 유지하며 권한을 업무 테이블로 정밀 부여.
  - `api_app`: 업무 테이블(addresses/orders/order_items/payments/payment_history) DML, `users`는 SELECT만(인증 원본은 못 씀).
  - `auth_app`: `users` DML.
- 커넥션 풀 캐시로 GRANT가 즉시 반영되지 않아 api 재시작으로 확인. init 순서도 스키마 생성 후 권한 부여로 정렬(05-accounts).

### 대안 비교
| 방식 | 판단 |
|---|---|
| RBAC만 | 객체 소유권을 못 막음(BOLA). 제외 |
| 공개 ID를 UUID로 불투명화 | 보조 수단. 소유권 검사를 대체하지 못함 |
| 서비스 계층에서 소유권 검사 | 가능하나 쿼리 누락 위험. **repository 쿼리 조건**이 더 안전 → 채택 |
| 403 vs 404 | 존재 은닉 위해 404 채택 |

## R — 재공격 결과

| 검사 | 결과 |
|---|---|
| 타인 주문 상세(다건) | 전부 404 |
| 타인 주소 수정(id 2~5) | 전부 404 |
| 본인 주문 상세 | 200 |
| 본인 주소 수정 | 200(권한 개선 후) |
| 무토큰 목록 | 401 |

verdict: cross_order_all_blocked=true, own_order_ok=true, no_token_401=true. 증거: `scenarios/v2/s1_result.json`.

## 자소서 한 줄 (초안)

로그인 사용자가 객체 ID만 바꿔 타인 주문·주소에 접근하는 BOLA 공격을 재현하고, 소유권을 repository 쿼리 조건까지 내려 전부 404로 차단했습니다. 이 과정에서 최소 권한 설정이 정상 쓰기를 막아 500을 내던 문제를 발견해 업무 테이블 단위로 권한을 재설계(인증 원본 테이블은 API가 못 쓰도록 분리)했습니다.
