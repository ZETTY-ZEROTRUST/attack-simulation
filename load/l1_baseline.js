// L-1 기준선: 로그인 → 마이페이지(주문·결제·주소 합성) → 주문 목록.
// step ramp로 knee(포화점)를 찾는다. 개선 없이 현재 코드 그대로 측정한다.
import { check, sleep } from 'k6';
import { login, authGet, seedEmail, tlsOption } from './common.js';

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    ramp: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 10 },
        { duration: '1m', target: 10 },
        { duration: '30s', target: 30 },
        { duration: '1m', target: 30 },
        { duration: '30s', target: 60 },
        { duration: '1m', target: 60 },
        { duration: '30s', target: 100 },
        { duration: '2m', target: 100 },
        { duration: '30s', target: 0 },
      ],
      gracefulStop: '10s',
    },
  },
  thresholds: {
    'http_req_duration{name:mypage}': ['p(95)<2000'],
    'http_req_failed': ['rate<0.05'],
  },
};

export default function () {
  const email = seedEmail(__VU * 1000 + __ITER);
  const token = login(email);
  if (!token) { sleep(1); return; }
  const mp = authGet('/mypage', token, 'mypage');
  check(mp, { 'mypage 200': (r) => r.status === 200 });
  const od = authGet('/orders', token, 'orders');
  check(od, { 'orders 200': (r) => r.status === 200 });
  sleep(1);
}
