"""
재시도/타임아웃 래퍼. 시뮬 도중 ALB 일시 장애에 죽지 않게.

call_api() — 모든 시나리오 공통.
  src_ip 인자가 주어지면 X-Forwarded-For 헤더에 박아 IP를 위조한다.
  ALB 기본 XFF 모드(append) + Nginx의 real_ip_recursive on +
  set_real_ip_from <ALB CIDR> 조합에서 ES 로그에 src_ip가
  client IP로 박힌다.

운영 endpoint는 영향 없음 — 위조가 통하는 조건은 LB/WAF/Nginx 정책에 따라
다르며, 본 시뮬은 그 정책이 느슨한(또는 시뮬 의도로 열어둔) 환경을 전제.
"""
import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(502, 503, 504),
        allowed_methods=("GET", "POST"),
    )
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def call_api(
    session,
    path: str,
    token: str,
    src_ip: str = None,
    timeout: float = 5.0,
):
    """
    공통 API 호출.

    Parameters
    ----------
    session  : requests.Session
    path     : 호출 경로 (예: "/api/addresses/140000002")
    token    : 위조 JWT
    src_ip   : 선택. 주어지면 X-Forwarded-For 헤더에 박는다.
               ASN map override에 등록된 IP를 넣어야 UBA factor에서 정상 동작.
    timeout  : 요청 타임아웃 (초)
    """
    base = os.environ["ZETI_ALB_URL"]
    url = f"{base.rstrip('/')}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    if src_ip:
        headers["X-Forwarded-For"] = src_ip
    return session.get(url, headers=headers, timeout=timeout)
