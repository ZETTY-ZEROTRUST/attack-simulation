"""
시나리오 실행 결과 기록 - 콘솔 1줄 출력 + JSONL 파일 저장.

각 시나리오는 ResultWriter 를 하나 만들어 매 요청 record() 를 호출한다.
  - 콘솔: 매 요청 간략 1줄 (시연 영상용)
  - 파일: results/{scenario}_{timestamp}.jsonl
          - 메타(시각/sub/위조IP/status/바이트) + api-server 응답 본문 전체

* results/ 에는 api-server 가 돌려준 PII(주소/전화/현관비번)가 그대로 담긴다.
  .gitignore 에 results/ 가 포함돼 있어야 하며, 시연 후 폐기를 권장한다.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Windows 콘솔(cp949)에서 stdout 이 파이프로 리다이렉트되면 일부 비-ASCII
# 문자(em-dash 등)에 UnicodeEncodeError 가 난다. UTF-8 로 재설정해 시연 중
# 출력 때문에 시나리오가 죽는 일을 막는다. (Python 3.7+ , 실패해도 무시)
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

_ROOT = Path(__file__).resolve().parent.parent
_RESULTS_DIR = _ROOT / "results"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_body(resp):
    """응답 본문 -> JSON object. 비-JSON이면 raw text(앞 2000자)로 보존.

    결과 기록이 시나리오를 죽이면 안 되므로 어떤 예외도 삼킨다.
    """
    try:
        return resp.json()
    except Exception:
        try:
            return {"_raw_text": (resp.text or "")[:2000]}
        except Exception:
            return None


class ResultWriter:
    """시나리오 1회 실행의 결과 파일 + 매 요청 콘솔 출력 담당."""

    def __init__(self, scenario: str):
        self.scenario = scenario
        self.prefix = f"[{scenario}]"
        self.total = 0
        self.ok = 0
        _RESULTS_DIR.mkdir(exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = _RESULTS_DIR / f"{scenario.lower()}_{stamp}.jsonl"
        self._fh = open(self.path, "w", encoding="utf-8")
        print(f"{self.prefix} 결과 파일: {self.path}")

    def record(self, sub, src_ip, method, uri, resp, **extra):
        """응답 1건 -> JSONL 1줄 + 콘솔 1줄. resp 는 requests.Response."""
        status = resp.status_code
        nbytes = len(resp.content)
        self._write({
            "ts": _now_iso(),
            "scenario": self.scenario,
            "victim_sub": sub,
            "src_ip": src_ip,
            "method": method,
            "uri": uri,
            "status": status,
            "resp_bytes": nbytes,
            "resp_body": _extract_body(resp),
            **extra,
        })
        self.total += 1
        if status == 200:
            self.ok += 1
        mark = "OK" if status == 200 else f"!{status}"
        print(f"{self.prefix} #{self.total} sub={sub} ip={src_ip or '-'} "
              f"{method} {uri} -> {mark} {nbytes}B")

    def record_error(self, sub, src_ip, uri, error, **extra):
        """네트워크 예외 등 응답 없는 실패 1건."""
        self._write({
            "ts": _now_iso(),
            "scenario": self.scenario,
            "victim_sub": sub,
            "src_ip": src_ip,
            "uri": uri,
            "status": None,
            "error": str(error),
            **extra,
        })
        self.total += 1
        print(f"{self.prefix} #{self.total} sub={sub} ip={src_ip or '-'} "
              f"{uri} -> ERROR {error}")

    def _write(self, record: dict):
        self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._fh.flush()   # 중단돼도 기록은 디스크에 남게

    def close(self) -> dict:
        """파일 닫고 요약 출력. 요약 dict 반환."""
        self._fh.close()
        fail = self.total - self.ok
        print(f"{self.prefix} 결과 저장 완료 - {self.total}건 "
              f"({self.ok} OK / {fail} 실패) -> {self.path}")
        return {"path": str(self.path), "total": self.total, "ok": self.ok}
