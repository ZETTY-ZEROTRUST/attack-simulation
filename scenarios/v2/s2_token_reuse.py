"""v2:S2 — 탈취 토큰 지속 사용. RT 회전·재사용 감지·family 폐기·로그아웃 반영을 검증한다.
로컬 secure 대상만. 토큰 원문은 결과에 남기지 않는다."""
import json
from common import login, get, run_meta, _req

def post(path, body):
    return _req("POST", path, body=body)

def login_full(email):
    st, body = post("/auth/login", {"email": email, "password": "loadtest-pw-1234"})
    d = json.loads(body)
    return d["accessToken"], d["refreshToken"]

def refresh(rt):
    st, body = post("/auth/refresh", {"refreshToken": rt})
    if st != 200:
        return st, None, None
    d = json.loads(body)
    return st, d["accessToken"], d["refreshToken"]

def main():
    meta = run_meta("v2:S2")
    r = {}

    # A. 정상 회전 → 구 RT 재사용 → family 폐기
    at0, rt0 = login_full("user001@zetty.test")
    st1, at1, rt1 = refresh(rt0)                 # 정상 회전
    r["rotate_ok"] = st1
    st_reuse, _, _ = refresh(rt0)                # 구(소비된) RT 재사용 = 공격
    r["reuse_old_rt"] = st_reuse
    st_after, _, _ = refresh(rt1)                # 재사용으로 family 폐기됐으므로 최신 RT도 거부돼야
    r["rotated_rt_after_reuse"] = st_after

    # B. 로그아웃 → 기존 AT가 다음 보호 요청에서 거부(authVersion 반영)
    at, rt = login_full("user002@zetty.test")
    r["me_before_logout"] = get("/users/me", at)[0]
    post("/auth/logout", {"refreshToken": rt})
    r["me_after_logout"] = get("/users/me", at)[0]     # 같은 AT
    r["refresh_after_logout"] = refresh(rt)[0]         # 폐기된 RT

    verdict = {
        "rotation_succeeds": r["rotate_ok"] == 200,
        "reuse_blocked_401": r["reuse_old_rt"] == 401,
        "family_revoked_on_reuse": r["rotated_rt_after_reuse"] == 401,
        "at_valid_before_logout": r["me_before_logout"] == 200,
        "at_rejected_after_logout": r["me_after_logout"] == 401,
        "rt_revoked_after_logout": r["refresh_after_logout"] == 401,
    }
    print(json.dumps({"meta": meta, "results": r, "verdict": verdict},
                     ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
