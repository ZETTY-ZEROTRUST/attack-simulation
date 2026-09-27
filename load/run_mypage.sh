#!/usr/bin/env bash
# 사용: [MEASURE=60s] run_mypage.sh <label> <rate> <dist> <repeats>
# 워밍업 30s(버림) 후 측정을 반복. DB SELECT/s와 /mypage 캐시 적중률을 Prometheus 델타로 기록.
set -u
LABEL=$1; RATE=$2; DIST=$3; REP=${4:-3}; MEASURE=${MEASURE:-60s}
cd "$(dirname "$0")/.."
PROM=http://127.0.0.1:9091/api/v1/query
q(){ curl -s "$PROM" --data-urlencode "query=$1" | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(sum(float(x["value"][1]) for x in r) if r else 0)'; }
# 측정 전에 빌드 컨테이너(Gradle)가 끝날 때까지 기다린다(같은 호스트 CPU 경합 방지).
waitbuild(){ while [ -n "$(docker ps -q --filter ancestor=eclipse-temurin:21-jdk)" ]; do sleep 10; done; }
k6(){ R=${3:-$RATE}; docker run --rm --add-host=host.docker.internal:host-gateway \
  -e BASE=https://host.docker.internal:8443 -e RATE=$R -e DURATION=$1 -e DIST=$DIST -e POOL_USERS=${POOL_USERS:-100} \
  -v "$PWD/load":/scripts grafana/k6:0.53.0 run --quiet --summary-export=/scripts/results/$2 /scripts/mypage_cache.js >/dev/null 2>&1; }
[ "${WARMUP:-30s}" != "0s" ] && k6 ${WARMUP:-30s} _warmup.json ${WARMUP_RATE:-$RATE}
for i in $(seq 1 $REP); do
  [ "${NOSLEEP:-0}" = 1 ] || sleep 6
  S0=$(q 'mysql_global_status_commands_total{command="select"}'); H0=$(q 'mypage_cache_requests_total{result="hit"}'); M0=$(q 'mypage_cache_requests_total{result="miss"}'); T0=$(date +%s)
  waitbuild
  k6 $MEASURE ${LABEL}_r$i.json
  B=$(docker ps -q --filter ancestor=eclipse-temurin:21-jdk); [ -n "$B" ] && echo "WARN ${LABEL}_r$i: build container overlapped measurement"
  sleep 6
  S1=$(q 'mysql_global_status_commands_total{command="select"}'); H1=$(q 'mypage_cache_requests_total{result="hit"}'); M1=$(q 'mypage_cache_requests_total{result="miss"}'); T1=$(date +%s)
  python3 - "$LABEL" "$i" "${MEASURE%s}" $S0 $S1 $H0 $H1 $M0 $M1 $T0 $T1 <<'PY'
import sys,json
L,i,dur,s0,s1,h0,h1,m0,m1,t0,t1=sys.argv[1],sys.argv[2],int(sys.argv[3]),*map(float,sys.argv[4:12])
m=json.load(open(f"load/results/{L}_r{i}.json"))["metrics"]; d=m["mypage_duration"]
hits,miss=h1-h0,m1-m0
hr=f"{hits/(hits+miss):.3f}" if hits+miss>0 else "-"
print(f"{L}_r{i} p50={d['med']:.1f} p95={d['p(95)']:.1f} ok={m['mypage_ok']['value']:.3f} rps={m['mypage_ok']['passes']/dur:.1f} dropped={m.get('dropped_iterations',{}).get('count',0)} db_select/s={(s1-s0)/dur:.0f} cache_hit={hr}")
PY
done
rm -f load/results/_warmup.json
