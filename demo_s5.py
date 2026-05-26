#!/usr/bin/env python3
"""demo_s5.py — S5 (IP Pool 분산 + sub 순차 enum) 단독 시연 진입점.

영상 흐름 (S5 전용):
  [터미널]   python demo_s5.py 실행 → S5 발사 + SSM trigger
  [Slack]    ~5분 wait → ASN 다양성(Route B) 알람 자동 pop
  [Kibana]   auto-refresh → 패널 spike

흐름:
  1. S5 발사 (IP 풀 분산, sub 100명 1회 순회, ~1.7분)
  2. S5 종료까지 대기 (콘솔에 진행 그대로 박힘 → 영상에 그대로 들어감)
  3. Filebeat → ELK 색인 wait 30초
  4. UBA 박스에 pipeline + phase3a 수동 trigger (SSM)

운영 메모:
  - SSM 명령 앞단에서 orchestrator-state.json 을 rm 하므로 throttle 우회됨 →
    demo_s2.py 와 연속으로 찍어도 OK. 운영 cron 영향 없음(같은 state 파일을
    뒤이은 cron_phase3a.sh 가 새로 만들어 사용).
  - S5 단독 score 가 phase3a 임계점에 못 미치면 알람이 안 뜰 수도 있음
    (직전 시연 출력 기준 max score 70). 임계 조정은 uba-analyzer 측 별도 작업.
"""
import os, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = ROOT / ".venv" / "bin" / "python"

print("=" * 60)
print("  ZETI 발표 시연 — S5 IP 분산 enum + 자동 UBA 분석")
print("=" * 60)

# === 1. S5 발사 ===
print("\n[1/3] 공격 시나리오 발사 — S5 (분산 enum, ~1.7분)")
proc = subprocess.Popen(
    [str(PY), "-u", "scenarios/s5_distributed.py"],
    cwd=str(ROOT),
)
print(f"  S5 PID = {proc.pid}  (51 IP × 100 sub 분산)")

# === 2. S5 종료까지 대기 + 색인 lag wait ===
proc.wait()
print("\n[2/3] S5 종료 — Filebeat → ELK 색인 wait (30초)")
for i in range(30, 0, -5):
    print(f"  ... {i}초 남음", flush=True)
    time.sleep(5)

# === 3. UBA 박스 SSM trigger — pipeline + phase3a ===
print("\n[3/3] UBA 박스 자동 trigger (pipeline + phase3a, ~5분)")
# 영상용: phase3a throttle/cost-guard state 를 매번 reset 해서 LLM 호출이
# 1/hour 락에 막히지 않도록 한다. JSON 파일 한 개라 안전하게 rm 으로 처리.
cmd = (
    "rm -f /opt/zeti-uba/logs/orchestrator-state.json && "
    "/opt/zeti-uba/scripts/cron_pipeline.sh && "
    "/opt/zeti-uba/scripts/cron_phase3a.sh"
)
result = subprocess.run([
    "aws", "ssm", "send-command",
    "--instance-ids", "i-0e06820c477644613",
    "--region", "ap-northeast-2",
    "--document-name", "AWS-RunShellScript",
    "--parameters", f'commands=["{cmd}"]',
    "--query", "Command.CommandId",
    "--output", "text",
], capture_output=True, text=True)
cmd_id = result.stdout.strip()
print(f"  SSM CommandId = {cmd_id}")

print("\n" + "=" * 60)
print("  S5 발사 완료 — 다음 자동:")
print("    Slack 채널 (#제티-UBA): ~5분 후 ASN 다양성(Route B) 알람 자동 pop")
print("    Kibana 대시보드        : auto-refresh 또는 F5 → 패널 spike")
print("=" * 60)
print(f"\n  cron 자동 (매 5분): /opt/zeti-uba/scripts/cron_pipeline.sh")
print(f"                      /opt/zeti-uba/scripts/cron_phase3a.sh")
print(f"\n  (지금은 *수동 trigger* — 영상 빠르게 위해)")
print(f"\n  ※ demo_s2.py 와 연속 촬영 OK")
print(f"     (각 demo 가 SSM 앞단에서 throttle state 를 reset 한다)")
