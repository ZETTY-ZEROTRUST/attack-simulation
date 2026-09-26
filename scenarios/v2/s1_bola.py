"""v2:S1 — 객체 단위 인가(BOLA). 정상 사용자가 남의 주문/주소 ID로 접근을 시도한다.
방어 기대: 타인 소유·부재 모두 404, 본인 자원은 200. 로컬 secure 대상만."""
import json
from common import login, get, run_meta

def find_owned_order_ids(token, limit=5):
    st, body = get("/orders?page=0&size=%d" % limit, token)
    if st != 200:
        return []
    return [o["orderId"] for o in json.loads(body)["content"]]

def main():
    meta = run_meta("v2:S1")
    a = login("user001@zetty.test")   # 공격자(정상 로그인 사용자)
    b = login("user002@zetty.test")   # 피해자
    assert a and b, "로그인 실패"

    victim_orders = find_owned_order_ids(b)          # 피해자가 실제 가진 주문 ID
    results = {"cross_order_detail": [], "own_order_detail": None,
               "cross_address_update": [], "no_token": None}

    # 1) 공격: 피해자 주문 ID로 상세 조회
    for oid in victim_orders:
        st, _ = get(f"/orders/{oid}/detail", a)
        results["cross_order_detail"].append({"order_id": oid, "status": st})

    # 2) 대조: 공격자 본인 주문은 성공해야 함
    own = find_owned_order_ids(a)
    if own:
        st, _ = get(f"/orders/{own[0]}/detail", a)
        results["own_order_detail"] = {"order_id": own[0], "status": st}

    # 3) 공격: 피해자 주소 수정 시도(순차 ID 추정)
    from common import _req
    for aid in range(1, 6):
        st, _ = _req("PUT", f"/addresses/{aid}", token=a,
                     body={"recipientName": "hijack", "recipientPhone": "010",
                           "postalCode": "00000", "addressLine1": "x", "addressLine2": "y",
                           "doorPassword": "0000", "deliveryNote": "z", "isDefault": True})
        results["cross_address_update"].append({"address_id": aid, "status": st})

    # 4) 무토큰
    st, _ = get("/orders", None)
    results["no_token"] = st

    # 판정
    cross = [r["status"] for r in results["cross_order_detail"]]
    blocked = all(s in (403, 404) for s in cross) if cross else None
    verdict = {
        "cross_order_all_blocked": blocked,
        "own_order_ok": results["own_order_detail"] and results["own_order_detail"]["status"] == 200,
        "no_token_401": results["no_token"] == 401,
    }
    print(json.dumps({"meta": meta, "results": results, "verdict": verdict},
                     ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
