"""v2:B0 — BFF 브라우저 공격. 로컬 secure 대상만. 토큰·쿠키 원문은 결과에 남기지 않는다(존재 여부만).

Before: /auth/login이 토큰을 클라이언트에 주는가
After : BFF에서 토큰 비노출, CSRF, 세션 고정, 로그아웃 후 쿠키 재사용, 프록시 우회, Authorization 끼워 넣기
"""
import http.cookiejar
import json
import re
import ssl
import time
import urllib.error
import urllib.request

BASE = "https://127.0.0.1:8443"
ORIGIN = "https://127.0.0.1:8443"
EVIL = "https://evil.example"
PW = "loadtest-pw-1234"
JWT_LIKE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class Browser:
    """쿠키를 자동 저장·전송하는 최소 브라우저 모사(HttpOnly 여부와 무관하게 전송은 된다)."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=CTX))

    def req(self, method, path, body=None, headers=None, raw_cookie=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(BASE + path, data=data, method=method)
        if body is not None:
            r.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        opener = self.opener
        if raw_cookie is not None:  # 쿠키 저장소를 쓰지 않고 지정한 쿠키만 보낸다(공격자 역할)
            r.add_header("Cookie", raw_cookie)
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX))
        try:
            with opener.open(r, timeout=10) as x:
                return x.status, x.read().decode(), dict(x.headers), x.headers.get_all("Set-Cookie") or []
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), dict(e.headers), e.headers.get_all("Set-Cookie") or []

    def session_cookie(self):
        for c in self.jar:
            if c.name == "__Host-zetty-session":
                return c
        return None


def login(b, email="user001@zetty.test", origin=ORIGIN):
    return b.req("POST", "/bff/login", {"email": email, "password": PW}, {"Origin": origin})


def main():
    r = {"run_id": f"v2:B0-{int(time.time())}"}

    # ---- Before: 토큰을 클라이언트에 주는 기존 경로 ----
    raw = Browser()
    st, body, _, _ = raw.req("POST", "/auth/login", {"email": "user001@zetty.test", "password": PW})
    r["before_auth_login_exposes_tokens"] = bool(st == 200 and JWT_LIKE.search(body))

    # ---- After 1: 토큰 비노출 + 쿠키 속성 ----
    b = Browser()
    st, body, hdr, set_cookies = login(b)
    csrf = json.loads(body)["csrfToken"] if st == 200 else None
    r["bff_login_status"] = st
    r["bff_login_body_has_token"] = bool(JWT_LIKE.search(body) or "accessToken" in body or "refreshToken" in body)
    sc = next((c for c in set_cookies if c.startswith("__Host-zetty-session=")), "")
    attrs = {a.strip().split("=")[0].lower() for a in sc.split(";")[1:]}
    r["cookie_attrs"] = sorted(attrs)
    r["cookie_ok"] = {"httponly", "secure", "path", "samesite"} <= attrs and "domain" not in attrs
    st2, body2, _, _ = b.req("GET", "/bff/session")
    r["bff_session_body_has_token"] = bool(JWT_LIKE.search(body2) or "accessToken" in body2)

    # ---- After 2: CSRF ----
    upd = {"name": "csrf-test", "phone": "010-0000-0000"}
    r["csrf_missing_token"] = b.req("PUT", "/bff/api/users/me", upd, {"Origin": ORIGIN})[0]
    r["csrf_evil_origin"] = b.req("PUT", "/bff/api/users/me", upd, {"Origin": EVIL, "X-CSRF-Token": csrf})[0]
    r["csrf_valid"] = b.req("PUT", "/bff/api/users/me", upd, {"Origin": ORIGIN, "X-CSRF-Token": csrf})[0]
    r["login_csrf_evil_origin"] = login(Browser(), origin=EVIL)[0]

    # ---- After 3: 세션 고정 ----
    victim = Browser()
    planted = "attacker-planted-session-id"
    st, _, _, _ = victim.req("POST", "/bff/login", {"email": "user002@zetty.test", "password": PW},
                             {"Origin": ORIGIN}, raw_cookie=f"__Host-zetty-session={planted}")
    # 공격자가 심어둔 ID로 접근 시도
    r["fixation_planted_id_after_login"] = Browser().req(
        "GET", "/bff/api/users/me", raw_cookie=f"__Host-zetty-session={planted}")[0]

    # ---- After 4: Authorization 끼워 넣기(다른 사용자 AT) ----
    other = Browser()
    _, obody, _, _ = other.req("POST", "/auth/login", {"email": "user002@zetty.test", "password": PW})
    other_at = json.loads(obody)["accessToken"]
    st, me, _, _ = b.req("GET", "/bff/api/users/me", headers={"Authorization": f"Bearer {other_at}"})
    r["injected_authorization_status"] = st
    r["injected_authorization_returned_user"] = json.loads(me).get("email") if st == 200 else None

    # ---- After 5: 오픈 프록시·경로 우회 ----
    probes = {
        "not_allowlisted": "/bff/api/lab/forge",
        "encoded_traversal": "/bff/api/..%2f..%2fauth/login",
        "dot_traversal": "/bff/api/users/../../auth/login",
        "absolute_url": "/bff/api/http://evil.example/",
        "actuator": "/bff/api/actuator/prometheus",
    }
    r["proxy_probes"] = {k: b.req("GET", p)[0] for k, p in probes.items()}

    # ---- After 6: 로그아웃 후 같은 쿠키 재사용(탈취 쿠키 재생) ----
    stolen = b.session_cookie().value
    lo = b.req("POST", "/bff/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": csrf})
    r["logout_status"] = lo[0]
    r["logout_revocation"] = lo[2].get("Zetty-Server-Revocation")
    r["stolen_cookie_after_logout"] = Browser().req(
        "GET", "/bff/api/users/me", raw_cookie=f"__Host-zetty-session={stolen}")[0]

    verdict = {
        "before_exposes_tokens": r["before_auth_login_exposes_tokens"] is True,
        "after_no_token_in_browser": not r["bff_login_body_has_token"] and not r["bff_session_body_has_token"],
        "cookie_attributes": r["cookie_ok"],
        "csrf_blocked": r["csrf_missing_token"] == 403 and r["csrf_evil_origin"] == 403 and r["csrf_valid"] == 200,
        "login_csrf_blocked": r["login_csrf_evil_origin"] == 403,
        "session_fixation_blocked": r["fixation_planted_id_after_login"] == 401,
        "injected_authorization_ignored": r["injected_authorization_returned_user"] == "user001@zetty.test",
        "proxy_bypass_blocked": all(v in (400, 404) for v in r["proxy_probes"].values()),
        "stolen_cookie_dead_after_logout": r["stolen_cookie_after_logout"] == 401,
    }
    print(json.dumps({"results": r, "verdict": verdict}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
