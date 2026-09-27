# attack-simulation

ZETTY **v2 공격 시나리오**. `backend`의 인증·인가·행동 이상을 실제로 공격해 방어·탐지를 검증한다.

## 시나리오 (`scenarios/v2/`)
- `start_jwt.py` — 변조·비정상 JWT 거부 (v2:start)
- `b0_bff_browser.py` — BFF 브라우저 공격 (토큰 탈취·CSRF·세션 고정·프록시 우회)
- `s1_bola.py` — BOLA (객체 소유권)
- `s2_token_reuse.py` — RT 회전·재사용 감지·폐기
- `s3_key_leak.py` — 서명키 유출 위조 → 발급대장
- `s4_behavior.py` — 행동 이상 트래픽(탐지 입력) + `s4_ground_truth.json`

STAR 문서: `docs/star/S-00 ~ S-06`. 부하 테스트: `load/`.

> v1(레거시) 시나리오·데모·문서(s2_token_hijack/s4_enumeration/s5/s5b/s6/s8, demo_*, run.sh, SCENARIOS.md)는 제거됨. 현재 활성 세트는 v2다.
