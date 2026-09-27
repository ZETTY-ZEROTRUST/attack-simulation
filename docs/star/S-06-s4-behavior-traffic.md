# S-06 v2:S4 행동 이상 트래픽·정답 manifest (log-pipeline 탐지 모델 입력)

- 상태: 완료(트래픽·manifest) · 탐지 모델은 log-pipeline(IsolationForest)
- 연결: 로드맵 S4 · log-pipeline C-02(SecurityEvent) · Z-05 파이프라인
- 작성/갱신: 2026-09-27

## S — 문제
S4는 인증·인가를 정상 통과한 뒤의 이상 사용이라 결정론적 차단(401/404)으로 못 잡는다. 탐지 모델(log-pipeline)이 학습·평가하려면 정상 대조군과 공격이 섞인 실제 이벤트, 그리고 **이벤트와 분리된 정답**이 필요하다.

## T — 목표
- 정상 대조군 + S4-A(과도 조회·burst·route 다양성)를 실제 스택에 흘려 SecurityEvent를 만든다.
- 정답(label)은 이벤트/ES에 넣지 않고 별도 manifest로 낸다. 공격자 식별은 HMAC 가명 키(subject_key)로만(신원 비노출).

## A — 어떻게
- `scenarios/v2/s4_behavior.py`: 모의 계정 정상 31명(좁은 route·완만) + 공격자 1명(넓은 route·20초 10스레드 burst).
- 공격자 subject_key는 프로브 요청의 응답 `X-Request-Id`로 그 이벤트를 ES에서 찾아 정확히 확보(이메일 미사용).
- manifest `scenarios/v2/s4_ground_truth.json`: run_id·window·정상 cohort·공격자 subject_key·변형·한계. **이벤트 스트림에는 label 없음.**

### 한계(정직)
- S4-B(다른 네트워크 동시 사용): edge IP가 동일해 부분만 재현.
- S4-C(발급대장 없는 과거 로그 사후분석): 과거 로그 주입 필요 — 미포함.

## R — 결과 (실측)
| 지표 | 값 |
|---|---|
| 정상 요청 / 공격자 요청 | 372 / 13,043(20초) |
| ES window 내 공격자 ACCESS_DECISION | 10,000, route 6종 |
| 정상 1인당(중앙값) | 12, route 2종 |
| 공격자 / 정상 중앙값 배수 | 약 833배 |
| 공격자 subject_key 확보 | 성공(가명) |

log-pipeline 탐지는 window·subject_key로 label을 붙여 학습/평가하고, 출처·표본·분모를 함께 보고한다. 여기서는 "탐지 성공"을 주장하지 않는다(모델은 log-pipeline 몫).

## 자소서 한 줄
인증을 통과한 뒤의 행동 이상(S4)을 재현하려고 정상 대조군과 공격 burst를 실제 이벤트로 만들고, 정답을 이벤트와 분리한 라벨 manifest(가명 키 기준)로 제공해 탐지 모델이 정답 누수 없이 학습·평가하도록 했습니다.
