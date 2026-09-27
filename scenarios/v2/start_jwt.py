"""v2:start — 표준 인증 기반. 변조·비정상 JWT를 API가 거부하는지 본다. 로컬 secure 대상만.

lab 위조기(auth-lab, profile lab, 실제 서명키로 임의 claim 서명)로 '서명은 유효하지만 조건 위반'
토큰을 만들어, 발급대장과 별개로 검증기 자체가 막는지 확인한다(발급대장은 lab 위조를 이미 막으므로
검증기 단독 방어를 보려면 lab 서명 + 대장 미기록 토큰이 필요하다).
"""
import base64
import json
import ssl
import time
import urllib.request
import urllib.error

BASE = "https://127.0.0.1:8443"
LAB = "http://127.0.0.1:8444"   # auth-lab (profile lab)
PW = "loadtest-pw-1234"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def code(method, path, headers=None, body=None, base=BASE):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    if body is not None:
        r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=10) as x:
            return x.status
    except urllib.error.HTTPError as e:
        return e.code


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def mypage(auth):
    return code("GET", "/mypage", {"Authorization": "Bearer " + auth})


def real_token():
    import urllib.request as u
    r = u.Request(BASE + "/auth/login", data=json.dumps(
        {"email": "user001@zetty.test", "password": PW}).encode(), method="POST")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, context=CTX, timeout=10) as x:
        return json.load(x)["accessToken"]


def forge(claims):
    """auth-lab이 실제 서명키로 임의 헤더·payload를 서명해 준다(대장 미기록)."""
    import urllib.request as u
    body = json.dumps(claims).encode()
    r = u.Request(LAB + "/lab/forge-claims", data=body, method="POST")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, context=CTX, timeout=10) as x:
        return x.read().decode()


def main():
    r = {"run_id": f"v2:start-{int(time.time())}"}
    now = int(time.time())

    # 정상 토큰(대조군)
    r["valid_token"] = mypage(real_token())

    # 서명 자체가 없는/깨진 토큰 — lab 없이도 가능
    none_tok = b64({"alg": "none", "typ": "at+jwt"}) + "." + b64(
        {"sub": "140000001", "iss": "https://auth.zeti.com/", "aud": "https://api.zeti.com",
         "jti": "x", "iat": now, "exp": now + 600}) + "."
    r["alg_none"] = mypage(none_tok)
    r["garbage"] = mypage("not.a.jwt")
    r["empty"] = mypage("")

    # lab 위조 토큰들(서명 유효·대장 미기록 → 검증기 단독 방어 확인)
    base = {"sub": "140000001", "iss": "https://auth.zeti.com/", "aud": "https://api.zeti.com",
            "jti": "lab-" + str(now), "authv": 0, "typ": "at+jwt",
            "iat": now, "nbf": now, "exp": now + 600}
    lab_up = None
    try:
        lab_up = forge(dict(base))
    except Exception as e:
        r["lab_available"] = f"no ({type(e).__name__})"
    if lab_up is not None:
        r["lab_available"] = "yes"
        variants = {
            "forged_but_valid_claims_not_in_ledger": dict(base),                 # 발급대장 방어(S3)
            "wrong_issuer": {**base, "iss": "https://evil.example/"},
            "wrong_audience": {**base, "aud": "https://other.api"},
            "wrong_typ": {**base, "typ": "JWT"},
            "no_exp": {k: v for k, v in base.items() if k != "exp"},
            "future_iat": {**base, "iat": now + 3600, "exp": now + 4200},
            "over_max_lifetime": {**base, "exp": now + 100000},
            "missing_sub": {k: v for k, v in base.items() if k != "sub"},
        }
        r["forged"] = {name: mypage(forge(c)) for name, c in variants.items()}

    verdict = {"valid_ok": r["valid_token"] == 200,
               "alg_none_blocked": r["alg_none"] == 401,
               "garbage_blocked": r["garbage"] == 401 and r["empty"] == 401}
    if "forged" in r:
        verdict["all_forged_blocked"] = all(v == 401 for v in r["forged"].values())
    print(json.dumps({"results": r, "verdict": verdict}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
