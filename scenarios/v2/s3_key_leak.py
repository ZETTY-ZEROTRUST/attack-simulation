"""v2:S3 — 서명키 유출로 토큰 위조. 공격자가 KMS Sign 권한을 얻어(lab forge) 유효 서명 토큰을 만든다.
방어 기대: 서명·kid가 유효해도 발급 대장에 없거나 digest/sub 불일치면 거부(401). 로컬 secure/lab만."""
import base64
import json
import ssl
import urllib.request
import urllib.error
from common import login, get, run_meta

LAB = "http://127.0.0.1:8444"

def forge(sub, authv=0, jti=None):
    url = f"{LAB}/lab/forge?sub={sub}&authv={authv}" + (f"&jti={jti}" if jti else "")
    with urllib.request.urlopen(urllib.request.Request(url, method="POST"), timeout=10) as r:
        return r.read().decode()

def jti_of(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))["jti"]

def main():
    meta = run_meta("v2:S3")
    r = {}

    # 0) 정상 발급 토큰은 대장에 있어 통과(대조군)
    real = login("user002@zetty.test")
    r["legit_token_me"] = get("/users/me", real)[0]

    # 1) 새 jti로 위조: 유효 서명·신뢰 kid, 그러나 대장 미기록
    forged_new = forge(140000002, 0)
    r["forged_new_jti_me"] = get("/users/me", forged_new)[0]

    # 2) 실제 jti 복사 + sub 변경 후 재서명: digest·sub 불일치
    stolen_jti = jti_of(real)
    forged_copy = forge(140000099, 0, jti=stolen_jti)
    r["forged_copied_jti_me"] = get("/users/me", forged_copy)[0]

    # 3) 존재하지 않는 주체로 위조
    forged_ghost = forge(999999999, 0)
    r["forged_ghost_me"] = get("/users/me", forged_ghost)[0]

    verdict = {
        "legit_ok": r["legit_token_me"] == 200,
        "forged_new_blocked": r["forged_new_jti_me"] == 401,
        "forged_copied_jti_blocked": r["forged_copied_jti_me"] == 401,
        "forged_ghost_blocked": r["forged_ghost_me"] == 401,
    }
    print(json.dumps({"meta": meta, "results": r, "verdict": verdict},
                     ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
