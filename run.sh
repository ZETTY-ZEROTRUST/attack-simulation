#!/usr/bin/env bash
#
# 발표 시연 일괄 실행.
# 사용법:
#   ./run.sh demo      # 발표 시연 (S4 15분 + S6 6h 압축) — S2 추가 예정
#   ./run.sh full      # 풀 시연 (S4 30분 + S6 24h) — S2 추가 예정
#   ./run.sh s4-only   # S4만
#   ./run.sh s6-only   # S6만
#
# ※ S2는 인프라 결정 후 통합 예정 (Nginx 시뮬 listener 등)
#
set -euo pipefail

cd "$(dirname "$0")"
source .env
export $(cut -d= -f1 .env)

case "${1:-demo}" in
  demo)
    echo "[run.sh] 발표 시연 모드 (S4 + S6, S2는 인프라 확정 후 통합)"
    python scenarios/s4_enumeration.py --duration 15 --rps 1.0 &
    S4_PID=$!
    python scenarios/s6_slow_low.py --duration 6 --min-interval 30 --max-interval 60 &
    S6_PID=$!
    wait $S4_PID $S6_PID
    ;;

  full)
    echo "[run.sh] 풀 시연 모드"
    python scenarios/s4_enumeration.py --duration 30 --rps 1.0 &
    python scenarios/s6_slow_low.py --duration 24 &
    wait
    ;;

  s4-only)
    python scenarios/s4_enumeration.py --duration 15 --rps 1.0
    ;;

  s6-only)
    python scenarios/s6_slow_low.py --duration 6
    ;;

  *)
    echo "사용법: $0 {demo|full|s4-only|s6-only}"
    exit 1
    ;;
esac
