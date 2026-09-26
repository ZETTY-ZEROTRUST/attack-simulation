# 부하 시험 하네스 (k6)

로컬 secure 대상(`https://host.docker.internal:8443`)에만 실행한다. 시드 계정 공용 비밀번호로 로그인한다.

```sh
# heavy 데이터 적재(사용자당 주문 대량) — L-2 병목 노출용
docker exec -i zetty-mysql-1 mysql -uroot -p"$MYSQL_ROOT_PASSWORD" < load/seed_heavy.sql

# 실행
docker run --rm --add-host=host.docker.internal:host-gateway \
  -e BASE=https://host.docker.internal:8443 -e HEAVY_USERS=20 \
  -v "$PWD/load":/scripts grafana/k6:0.53.0 \
  run --summary-export=/scripts/results/<name>.json /scripts/l2_heavy.js
```

- `l1_baseline.js`: 로그인→마이페이지→주문목록 step ramp. knee 탐색.
- `l2_heavy.js`: 주문 많은 사용자에 마이페이지·목록 부하(L-2).
- `results/`: k6 summary JSON. 커밋해 전/후 비교 근거로 남긴다.

결과 해석·개선 근거는 `../backend/docs/star/B-02` 참조.
