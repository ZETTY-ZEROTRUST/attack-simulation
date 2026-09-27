"""v2:S4 — 인증 통과 뒤 행동 이상. 정상 대조군 + S4-A(과도 조회·burst·route 다양성)를 실제 스택에 흘린다.
정답(label)은 이벤트에 넣지 않고 별도 manifest로 낸다. 공격자 식별은 가명 키(subject_key)로만.
로컬 secure/모의 계정 전용. 토큰 원문은 결과에 남기지 않는다."""
import concurrent.futures as cf
import json
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE = "https://127.0.0.1:8443"
PW = "loadtest-pw-1234"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

NORMAL_USERS = [f"user{n:03d}@zetty.test" for n in range(300, 331)]  # 정상 대조군 31명
ATTACKER = "user399@zetty.test"                                      # 탈취 가정 모의 계정
NORMAL_ROUTES = ["/mypage", "/users/me"]                             # 정상: 좁은 route
ALL_ROUTES = ["/mypage", "/users/me", "/orders?page=0&size=20", "/addresses",
              "/payments/balance", "/payments/history"]              # 공격: 넓은 route


def login(email):
    r = urllib.request.Request(BASE + "/auth/login",
                               data=json.dumps({"email": email, "password": PW}).encode(),
                               method="POST")
    r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, context=CTX, timeout=10) as x:
        return json.load(x)["accessToken"]


def get_with_headers(path, token):
    r = urllib.request.Request(BASE + path)
    r.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(r, context=CTX, timeout=10) as x:
        return x.status, dict(x.headers)


def get(path, token):
    r = urllib.request.Request(BASE + path)
    r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=10) as x:
            return x.status
    except urllib.error.HTTPError as e:
        return e.code


def normal_user(email):
    """정상 사용자: 로그인 후 좁은 route를 느긋하게 몇 번."""
    tok = login(email)
    n = 0
    for _ in range(6):
        for path in NORMAL_ROUTES:
            get(path, tok)
            n += 1
        time.sleep(0.4)
    return n


def attacker_burst(email, seconds=20):
    """S4-A: 자기 권한 안에서 넓은 route를 고속으로 대량 조회(burst)."""
    tok = login(email)
    stop = time.time() + seconds
    count = [0]

    def hammer(i):
        c = 0
        while time.time() < stop:
            get(ALL_ROUTES[c % len(ALL_ROUTES)], tok)
            c += 1
        return c

    with cf.ThreadPoolExecutor(10) as ex:
        for c in ex.map(hammer, range(10)):
            count[0] += c
    return count[0]


def es(path, body=None):
    cmd = ["docker", "exec", "zetty-elasticsearch-1", "curl", "-s",
           "-H", "Content-Type: application/json", "http://localhost:9200" + path]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    return json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)




def main():
    run_id = f"v2:S4-{int(time.time())}"
    t0 = time.gmtime()
    window_start = time.strftime("%Y-%m-%dT%H:%M:%SZ", t0)

    # 공격자 subject_key를 정확히 확보: 프로브 요청의 응답 X-Request-Id로 그 요청의 이벤트를 찾는다.
    atk_tok = login(ATTACKER)
    _, hdr = get_with_headers("/mypage", atk_tok)
    probe_rid = hdr.get("X-Request-Id") or hdr.get("x-request-id")
    atk_key = None
    for _ in range(10):
        time.sleep(1)
        es("/zetty-security-events-v2-*/_refresh")
        hits = es("/zetty-security-events-v2-*/_search",
                  {"size": 1, "query": {"term": {"request_id": probe_rid}},
                   "_source": ["actor.subject_key"]})["hits"]["hits"]
        if hits and hits[0]["_source"].get("actor", {}).get("subject_key"):
            atk_key = hits[0]["_source"]["actor"]["subject_key"]; break

    # 정상 대조군(병렬)
    with cf.ThreadPoolExecutor(8) as ex:
        normal_reqs = sum(ex.map(normal_user, NORMAL_USERS))

    # S4-A 공격 burst
    atk_reqs = attacker_burst(ATTACKER, seconds=20)

    window_end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    manifest = {
        "run_id": run_id,
        "scenario": "v2:S4-A",
        "description": "정상 대조군 + 공격자 burst(넓은 route 고속 대량 조회). 인증·인가는 통과, 행동만 이상.",
        "window": {"start": window_start, "end": window_end},
        "normal_cohort": {"users": len(NORMAL_USERS), "approx_requests": normal_reqs,
                          "routes": NORMAL_ROUTES, "pace": "완만"},
        "attacker": {"subject_key": atk_key, "approx_requests": atk_reqs,
                     "routes": ALL_ROUTES, "pace": "20초 동안 10 스레드 burst"},
        "label_note": "이벤트에는 label이 없다. subject_key가 공격자, window 안에서 판정. subject_key는 HMAC 가명이라 신원 아님.",
        "limits": ["S4-B(다른 네트워크 동시 사용)는 edge IP가 동일해 부분만 재현",
                   "S4-C(발급대장 없는 과거 로그 사후분석)는 별도 과거 로그 주입 필요 — 미포함"],
    }
    # 정답 manifest는 별도 파일. 이벤트 스트림·ES에는 넣지 않는다.
    out = "scenarios/v2/s4_ground_truth.json"
    with open(out, "w") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(json.dumps({"run_id": run_id, "manifest": out,
                      "normal_requests": normal_reqs, "attacker_requests": atk_reqs,
                      "attacker_subject_key_found": bool(atk_key), "probe_request_id": probe_rid}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
