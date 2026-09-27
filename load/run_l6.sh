#!/usr/bin/env bash
# 사용: [MEASURE=60s] run_l6.sh <label> <rate>
# /mypage(hot) 부하 중 파이프라인 적체를 5초 간격으로 기록하고, 구간 처리량을 Prometheus 증가량으로 계산한다.
set -u
LABEL=$1; RATE=$2; MEASURE=${MEASURE:-60s}; DUR=${MEASURE%s}
cd "$(dirname "$0")/.."
PROM=http://127.0.0.1:9091/api/v1/query
q(){ curl -s "$PROM" --data-urlencode "query=$1" | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(round(sum(float(x["value"][1]) for x in r),1) if r else "-")'; }
waitquiet(){ while [ -n "$(docker ps -q --filter ancestor=eclipse-temurin:21-jdk)$(docker ps -q --filter name=p02test-)" ]; do sleep 10; done; }
drain(){ for i in $(seq 1 60); do P=$(q 'sum(zetty_relay_pending_rows)'); [ "$P" = "0.0" ] || [ "$P" = "-" ] && break; sleep 5; done; }
k6(){ docker run --rm --add-host=host.docker.internal:host-gateway -e BASE=https://host.docker.internal:8443 \
  -e RATE=$RATE -e DURATION=$1 -e DIST=hot -e POOL_USERS=100 -v "$PWD/load":/scripts grafana/k6:0.53.0 \
  run --quiet --summary-export=/scripts/results/$2 /scripts/mypage_cache.js >/dev/null 2>&1; }
LOG=load/results/${LABEL}_pipeline.log; : > $LOG
waitquiet; k6 30s _warm_l6.json; drain
( while true; do echo "$(date +%H:%M:%S) pending_rows=$(q 'sum(zetty_relay_pending_rows)') lag_s=$(q 'max(zetty_relay_lag_seconds)') indexer_pending=$(q 'sum(zetty_indexer_pending)')" >> $LOG; sleep 5; done ) & S=$!
k6 $MEASURE ${LABEL}.json
kill $S; sleep 6
python3 - "$LABEL" "$DUR" \
  "$(q "sum(increase(mysql_global_status_commands_total{command=\"insert\"}[${DUR}s]))")" \
  "$(q "sum(increase(zetty_relay_published_total[${DUR}s]))")" \
  "$(q "sum(increase(zetty_indexer_indexed_total[${DUR}s]))")" <<'PY'
import sys,json
L,dur,ins,pub,idx=sys.argv[1],int(sys.argv[2]),*sys.argv[3:6]
m=json.load(open(f"load/results/{L}.json"))["metrics"]; d=m["mypage_duration"]
f=lambda v: f"{float(v)/dur:.0f}" if v not in ("-",) else "-"
print(f"{L} p50={d['med']:.1f}ms p95={d['p(95)']:.1f}ms ok={m['mypage_ok']['value']:.3f} rps={m['mypage_ok'].get('passes',0)/dur:.0f} dropped={m.get('dropped_iterations',{}).get('count',0)} db_insert/s={f(ins)} relay_published/s={f(pub)} indexed/s={f(idx)}")
PY
echo "  적체 추이(처음·중간·끝):"; sed -n '1p;6p;$p' $LOG | sed 's/^/    /'
rm -f load/results/_warm_l6.json
