# S4 HTTP 정답 데이터 생성

GitHub 공개 자료의 재현 학습과 별도로, **정상·유효 토큰 악용 행동이 알려진 로컬 평가 자료**를 만든다. 실제 사고 데이터나 실제 토큰 탈취 성공 자료가 아니다.

## 실행

```bash
# attack-simulation 디렉터리
python3 -m unittest discover -s datasets/s4_http -v
python3 datasets/s4_http/runner.py
```

표준 라이브러리만 사용한다. 실행 중인 ZETTY core·이벤트 파이프라인과 Docker CLI, 기존 모의 계정, compose/tls/ca.crt가 필요하다. 서비스 설정·DB·키를 변경하지 않는다.

기본값: 계정 20개, 실제 60초 창 10개, 동시 요청 4개, 최대 15,000 요청·900초. 학습 3분 정상-only, 보정 2분 정상-only, 테스트 5분에서 actor-window 100개 중 정상 95·공격 5. 테스트 비율은 요청량 비율이 아니다. 실제 창을 복제하거나 시간값을 바꿔 표본 수를 늘리지 않는다.

정상 느린 조회·고활동·짧은 피크를 포함한다. S4-A는 유효한 모의 토큰으로 자기 권한 안에서 반복·burst·조회 범위를 확대한다. 동일 계정이 정상 학습 뒤 테스트에서 악용 행동으로 전환할 수 있다. 로그인·발급대장과 무관한 자동 차단으로 정답이 정해지지 않는다.

## 산출물과 피처 계약

새 실행마다 `results/s4-http/<UTC run_id>/`를 만든다. 기존 실행을 덮어쓰지 않으며 결과 디렉터리는 Git에서 제외된다.

| 파일 | 용도 |
|---|---|
| observations.jsonl | 요청 관측: request_id, 익명 cohort_id, UTC 시각, 실제 창 안 offset, method, canonical route, status, latency_ms, client_observed_body_bytes, 오류 클래스 |
| ground_truth.jsonl / labels.csv | window_id, label(정상0·공격1), split, profile, cohort_id, UTC 창 시작/종료 |
| features.csv | window_id와 수치 피처 14개 |
| actor_mapping.json | request_id→API ACCESS_DECISION의 검증된 actor.subject_key 연결 근거 |
| quality.json | 성공 여부, 오류·거부·중복·누락·불완전 창·split 표본 수 |
| manifest.json | schema_version=zetty.s4-http/1, dataset_version=1, 실행 설정·시간·파일 SHA256·피처 출처 |
| failure.json | 중단한 실행의 오류 유형·완료 분모(실패 시에만) |

수치 피처: request_count, mean_interval_s, interval_std_s, distinct_uri_count, response_bytes_sum, response_bytes_mean, response_bytes_std, 4xx_ratio, 5xx_ratio, GET_ratio, POST_ratio, burst_max_per_s, GET_count, successful_2xx_count.

- interval은 실제 요청 시작 시각 차이이며 원본 방식처럼 첫 0을 포함한다. 평균 분모는 요청 수다.
- 표준편차는 sample ddof=1, singleton=0.
- 요청 route는 query를 제거한 템플릿이다.
- 응답 크기는 **클라이언트가 받은 본문의 byte 수**다. backend 응답 크기 필드가 null인 현재 상태와 출처를 구분한다. 본문을 저장하지 않는다.
- 모든 요청은 GET이다. GET/POST 피처는 이 실험에서 상수일 수 있다.
- IP는 모두 loopback이므로 사용자 식별/모델 피처로 쓰지 않는다.
- window_id·label·split·profile·cohort_id·request_id·절대 시각·subject_key는 모델에 입력하지 않는다.

## 품질과 한계

실패·비2xx·request_id 누락/중복·이벤트 연결 누락·사용자 매핑 불일치·창 범위 위반은 quality fail이다. 정상이었던 것으로 바꾸거나 오류 행을 제거해 성능을 부풀리지 않는다. 학습 담당은 manifest 완료와 quality pass를 확인한 뒤 파일을 읽어야 한다.

TLS CA 검증, 환경 proxy 우회, redirect 거부, 대상 loopback 고정, 응답·timeout·동시성·요청량·실행 시간 상한을 적용한다. split마다 로그인하고 최대 14분으로 제한해 900초 토큰 유효시간 내에 끝낸다. 토큰·쿠키·비밀번호·이메일·본문은 결과에 저장하지 않는다. 기존 공개 시나리오의 모의 fixture만 런타임 메모리로 사용한다.

테스트 100개에서 공격은 5개뿐이다. 정상 calibration 40개로 1% 오탐 임계값을 안정적으로 추정할 수 없다. 큰 표본 확대는 실제 추가 capture·독립 seed·계정/시간/공격 양상 다양화가 필요하다. 95:5와 99:1은 실험 비율이며 실제 침해율 근거가 아니다.

## 완료한 확대 실행

기존 모의 계정100개 로그인 검증100/100 성공 후 다음 명령을 실제 실행했다.

```bash
python3 datasets/s4_http/runner.py --actors 100 --train-windows 2 \
  --calibration-windows 2 --test-windows 10 --max-requests 65000 \
  --max-seconds 1100 --seed 20261004
```

| 항목 | 실제 결과 |
|---|---:|
| API 조회 요청(로그인 제외) | 53,983 |
| actor×실제60초 창 | 1,400 |
| 정상 학습 / 정상 보정 창 | 200 / 200 |
| 테스트 정상 / 공격 창 | 950 / 50 (95:5) |
| 테스트 정상 / 공격 요청 | 33,660 / 6,020 (약84.83:15.17) |
| 캡처 시작 이후 경과 시간 | 936.09초 |
| 관측 오류·비2xx·ID 누락/중복·검증 actor 연결 누락 | 모두0 |
| verified actor 수 | 100 |
| 조회 client latency 중앙값 / p95 | 8.409 / 13.608ms |
| S4 repeated / burst / broad 구간 | 17 / 17 / 16 |

현재 workspace 결과는 `results/s4-http/20261003T112322246307Z/`에 있다. 이 디렉터리는 Git ignored다.

- [실행 manifest](../../results/s4-http/20261003T112322246307Z/manifest.json)
- [품질 검증](../../results/s4-http/20261003T112322246307Z/quality.json)
- [버전 관리되는 안전한 집계 근거](../../docs/star/results/S-07-expanded-summary.json)
- [STAR 결과와 한계](../../docs/star/S-07-s4-http-labeled-dataset.md)

profile_version=2-overlapping-normal-peaks에서 정상 burst는60~120회/분, 공격은100~140회/분으로 요청량이 겹친다. 첫 파일럿은 정상 burst48회/분이었고 시작 시점 소스 snapshot이 없어, 현재 기본 명령을 다시 실행하면 최초 파일럿과 정확히 같은 생성 분포가 아니다. 첫 파일럿200창·5,532조회와 확대1,400창·53,983조회는 **각각 다른 생성 분포의 독립 자료**다. 파일럿과 확대 간 지표 차이를 모델 개선 효과로 주장하지 않는다.

936.09초는 첫 capture 시작부터 split 사이 로그인·마지막 검증까지의 경과 시간이다. 최초 계정 로그인·별도 계정 선행 검증 시간은 포함하지 않는다. latency는 이 로컬 모의 조회 실험의 클라이언트 관측값이며 운영 서비스 성능을 뜻하지 않는다. 동일100개 모의 계정의 시간 분리 평가이고 신규 사용자 일반화 평가는 아니다.

## 더 큰 평가 계획

10,000개의 실제1분 테스트 창은 계정100개 기준100분이며 현 runner의 split별 토큰 TTL 상한을 넘어 반복 capture 설계가 필요하다. 여러 독립 실행의 train/calibration/test를 미리 정하고 동일 창을 복제하지 않는다. 99:1 평가 패널도 아직 생성하지 않았다. 정상100명·테스트10분(1,000창)에 공격10창이면99:1을 구성할 수 있지만 공격유형별 분모가 작다는 한계가 있다.
