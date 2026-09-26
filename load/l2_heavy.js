// L-2: 주문이 많은 사용자(heavy)에 마이페이지·주문목록 부하.
// 병목 가설: listByUserId가 전체 주문을 읽고 mypage는 5건만 사용, orders는 전량 직렬화.
import { check, sleep } from 'k6';
import { login, authGet, tlsOption } from './common.js';

const HEAVY = parseInt(__ENV.HEAVY_USERS || '20', 10);

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    ramp: {
      executor: 'ramping-vus', startVUs: 0,
      stages: [
        { duration: '20s', target: 20 },
        { duration: '1m', target: 20 },
        { duration: '20s', target: 50 },
        { duration: '1m30s', target: 50 },
        { duration: '20s', target: 0 },
      ],
      gracefulStop: '10s',
    },
  },
  thresholds: { 'http_req_failed': ['rate<0.05'] },
};

function heavyEmail(i) {
  const n = String((i % HEAVY) + 1).padStart(3, '0');
  return `user${n}@zetty.test`;
}

// 로그인 비용을 분리하려고 VU당 토큰을 1회 발급해 재사용한다.
export default function () {
  if (!__ENV._t) { /* noop */ }
  const email = heavyEmail(__VU);
  const token = login(email);
  if (!token) { sleep(1); return; }
  for (let i = 0; i < 5; i++) {
    check(authGet('/mypage', token, 'mypage'), { 'mypage 200': (r) => r.status === 200 });
    check(authGet('/orders', token, 'orders'), { 'orders 200': (r) => r.status === 200 });
    sleep(0.5);
  }
}
