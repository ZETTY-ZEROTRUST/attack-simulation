"""/mypage 캐시 정합성 시험.
읽기 부하를 거는 동안 프로필 이름을 버전 문자열(v1, v2, ...)로 갱신한다.
PUT 성공 응답을 받은 시각 이후 /mypage가 옛 버전을 돌려준 비율과, 최신 버전이 보일 때까지 걸린 시간을 잰다.
HTTP 200 여부가 아니라 반환된 버전으로 판정한다. 로컬 secure 대상만."""
import json, os, ssl, subprocess, sys, threading, time, urllib.request, urllib.error

BASE = "https://127.0.0.1:8443"
MODE = os.environ.get("WRITE_MODE", "api")  # api | sql
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

def req(method, path, token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if body is not None: r.add_header("Content-Type", "application/json")
    if token: r.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=10) as x: return x.status, x.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def main(email="user003@zetty.test", versions=10, readers=8, gap=1.5):
    st, b = req("POST", "/auth/login", body={"email": email, "password": "loadtest-pw-1234"})
    tok = json.loads(b)["accessToken"]
    latest = {"v": None, "t": None}
    stale, total, lags = 0, 0, []
    failed_writes = []
    seen_fresh = {}
    stop = threading.Event()
    lock = threading.Lock()

    def reader():
        nonlocal stale, total
        while not stop.is_set():
            started = time.time()           # 요청을 보낸 시각
            st, b = req("GET", "/mypage", tok)
            now = time.time()
            if st != 200: continue
            name = json.loads(b)["user"]["name"]
            with lock:
                # 쓰기 성공 확인 이후에 출발한 읽기만 판정한다(진행 중이던 읽기 제외).
                if latest["v"] is None or started < latest["t"]: continue
                total += 1
                if name != latest["v"]:
                    stale += 1
                elif latest["v"] not in seen_fresh:
                    seen_fresh[latest["v"]] = now - latest["t"]

    ts = [threading.Thread(target=reader, daemon=True) for _ in range(readers)]
    for t in ts: t.start()
    for i in range(1, versions + 1):
        v = f"v{i}-{int(time.time()*1000)}"
        if MODE == "sql":
            # 앱을 거치지 않는 쓰기(배치·운영자 수정): 캐시 무효화가 일어나지 않는다.
            r = subprocess.run(["docker", "exec", "-i", "-e", "MYSQL_PWD=" + os.environ["MYSQL_ROOT_PASSWORD"],
                                "zetty-mysql-1", "mysql", "-uroot", "-N", "-e",
                                f"UPDATE zeti_db.users SET name='{v}' WHERE email='{email}'"],
                               capture_output=True)
            st = 200 if r.returncode == 0 else 500
        else:
            st, _ = req("PUT", "/users/me", tok, {"name": v, "phone": "010-0000-0000"})
        with lock:
            if st == 200:
                latest["v"], latest["t"] = v, time.time()   # 성공 확인 시점 기준
            else:
                failed_writes.append(st)
        time.sleep(gap)
    stop.set()
    for t in ts: t.join(timeout=3)
    lag = list(seen_fresh.values())
    print(json.dumps({
        "write_mode": MODE,
        "reads_after_write": total, "stale_reads": stale,
        "stale_ratio": round(stale / total, 4) if total else None,
        "versions_seen_fresh": len(lag), "versions_written": versions, "failed_writes": failed_writes,
        "time_to_fresh_ms_max": round(max(lag) * 1000, 1) if lag else None,
        "time_to_fresh_ms_avg": round(sum(lag) / len(lag) * 1000, 1) if lag else None,
    }, ensure_ascii=False))

if __name__ == "__main__":
    main()
