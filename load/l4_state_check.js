// L-4: 보호 요청마다 MySQL authVersion 대조(S2 도입) 비용 측정.
// VU당 토큰 1회 발급 후 /users/me를 반복 → 로그인 비용을 배제하고 상태확인 경로만 부하.
import { check, sleep } from 'k6';
import { login, authGet, seedEmail, tlsOption } from './common.js';

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    ramp: {
      executor: 'ramping-vus', startVUs: 0,
      stages: [
        { duration: '20s', target: 25 },
        { duration: '1m', target: 25 },
        { duration: '20s', target: 75 },
        { duration: '1m30s', target: 75 },
        { duration: '20s', target: 0 },
      ],
      gracefulStop: '10s',
    },
  },
  thresholds: { 'http_req_failed': ['rate<0.05'], 'http_req_duration{name:me}': ['p(95)<1000'] },
};

export function setup() {
  // 소수의 실제 토큰을 미리 발급해 VU가 공유(로그인 부하 제외).
  const tokens = [];
  for (let i = 0; i < 25; i++) {
    const t = login(seedEmail(i));
    if (t) tokens.push(t);
  }
  return { tokens };
}

export default function (data) {
  const token = data.tokens[__VU % data.tokens.length];
  if (!token) { sleep(1); return; }
  check(authGet('/users/me', token, 'me'), { 'me 200': (r) => r.status === 200 });
  sleep(0.2);
}
