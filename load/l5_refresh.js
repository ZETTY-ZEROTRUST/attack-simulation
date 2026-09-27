// L-5: Auth 서버 /auth/refresh 부하. RT는 1회용이라 VU가 받은 새 RT로 체이닝한다.
// refresh 1건 = RT 해시조회 + 소비(update) + 새 RT insert + 발급대장 insert (쓰기 위주).
import { check, sleep } from 'k6';
import http from 'k6/http';
import { BASE, PASSWORD, seedEmail, tlsOption } from './common.js';

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    ramp: {
      executor: 'ramping-vus', startVUs: 0,
      stages: [
        { duration: '20s', target: 20 },
        { duration: '1m', target: 20 },
        { duration: '20s', target: 50 },
        { duration: '1m', target: 50 },
        { duration: '20s', target: 0 },
      ],
      gracefulStop: '10s',
    },
  },
  thresholds: { 'http_req_failed': ['rate<0.05'], 'http_req_duration{name:refresh}': ['p(95)<2000'] },
};

export function setup() {
  const rts = [];
  for (let i = 0; i < 60; i++) {
    const r = http.post(`${BASE}/auth/login`,
      JSON.stringify({ email: seedEmail(i), password: PASSWORD }),
      { headers: { 'Content-Type': 'application/json' } });
    if (r.status === 200) rts.push(r.json('refreshToken'));
  }
  return { rts };
}

// VU-local 현재 RT
let myRt = null;

export default function (data) {
  if (myRt === null) {
    myRt = data.rts[(__VU - 1) % data.rts.length];
  }
  const r = http.post(`${BASE}/auth/refresh`,
    JSON.stringify({ refreshToken: myRt }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'refresh' } });
  const ok = check(r, { 'refresh 200': (res) => res.status === 200 });
  if (ok) {
    myRt = r.json('refreshToken');   // 회전된 새 RT로 교체
  } else {
    myRt = null;                     // 실패 시 다음 iter에 새 RT 배정
  }
  sleep(0.3);
}
