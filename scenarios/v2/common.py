"""v2 시나리오 공용: 로컬 secure 대상 전용. 토큰 원문·키는 결과에 남기지 않는다."""
import json
import ssl
import time
import urllib.request
import urllib.error

BASE = "https://127.0.0.1:8443"
PASSWORD = "loadtest-pw-1234"
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # 로컬 self-signed


def _req(method, path, token=None, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def login(email):
    st, body = _req("POST", "/auth/login", body={"email": email, "password": PASSWORD})
    if st != 200:
        return None
    return json.loads(body)["accessToken"]


def get(path, token):
    return _req("GET", path, token=token)


def run_meta(name):
    return {"scenario": name, "run_id": f"{name}-{int(time.time())}", "base": BASE}
