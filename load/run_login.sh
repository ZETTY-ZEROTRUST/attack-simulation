#!/usr/bin/env bash
# 사용: [MEASURE=60s] run_login.sh <label> <rate>
# 측정 구간 동안 auth·kms·mysql 컨테이너 CPU(코어 수)를 cAdvisor로 기록한다.
set -u
LABEL=$1; RATE=$2; MEASURE=${MEASURE:-60s}; DUR=${MEASURE%s}
cd "$(dirname "$0")/.."
PROM=http://127.0.0.1:9091/api/v1/query
waitquiet(){ while [ -n "$(docker ps -q --filter ancestor=eclipse-temurin:21-jdk)$(docker ps -q --filter name=p02test-)" ]; do sleep 10; done; }
cpu(){ ID=$(docker inspect --format '{{.Id}}' "$1" 2>/dev/null); curl -s "$PROM" --data-urlencode "query=sum(rate(container_cpu_usage_seconds_total{id=\"/docker/$ID\"}[${DUR}s]))" | python3 -c 'import sys,json;r=json.load(sys.stdin)["data"]["result"];print(round(float(r[0]["value"][1]),2) if r else "-")'; }
k6(){ docker run --rm --add-host=host.docker.internal:host-gateway -e BASE=https://host.docker.internal:8443 \
  -e RATE=$RATE -e DURATION=$1 -v "$PWD/load":/scripts grafana/k6:0.53.0 run --quiet --summary-export=/scripts/results/$2 /scripts/login_rate.js >/dev/null 2>&1; }
waitquiet
k6 20s _warm_login.json
waitquiet
k6 $MEASURE ${LABEL}.json
sleep 5
OV=$(docker ps -q --filter name=p02test-); [ -n "$OV" ] && echo "WARN ${LABEL}: p02test 컨테이너가 측정 중 실행됨"
A2=$(docker ps -q --filter name=zetty-auth-2 >/dev/null 2>&1 && cpu zetty-auth-2)
python3 - "$LABEL" "$DUR" "$(cpu zetty-auth-1)" "$(cpu zetty-kms-1)" "$(cpu zetty-mysql-1)" "${A2:--}" <<'PY'
import sys,json
L,dur,ca,ck,cm,ca2=sys.argv[1],int(sys.argv[2]),*sys.argv[3:7]
m=json.load(open(f"load/results/{L}.json"))["metrics"]; d=m["login_duration"]
a=m.get("login_accepted_duration",{}); rj=m.get("login_rejected_429",{}).get("value",0)
print(f"{L} accepted_p50={a.get('med',0):.0f}ms accepted_p95={a.get('p(95)',0):.0f}ms rejected429={rj:.3f} all_p95={d['p(95)']:.0f}ms ok={m['login_ok']['value']:.3f} tps={m['login_ok'].get('passes',0)/dur:.1f} dropped={m.get('dropped_iterations',{}).get('count',0)} cpu(auth1/2.0)={ca} cpu(auth2/2.0)={ca2} cpu(kms/0.5)={ck} cpu(mysql/2.0)={cm}")
PY
rm -f load/results/_warm_login.json
