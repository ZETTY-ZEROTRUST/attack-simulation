// L-5: POST /auth/login만 일정 유입률로 부하. 반복당 요청 1건, 사용자 순환.
import { check } from 'k6';
import http from 'k6/http';
import { Trend, Rate } from 'k6/metrics';
import { BASE, PASSWORD, seedEmail } from './common.js';

const RATE = parseInt(__ENV.RATE || '20', 10);
const loginDur = new Trend('login_duration', true);
const loginOk = new Rate('login_ok');
const acceptedDur = new Trend('login_accepted_duration', true); // 200만
const rejected = new Rate('login_rejected_429');

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    fixed: {
      executor: 'constant-arrival-rate', rate: RATE, timeUnit: '1s',
      duration: __ENV.DURATION || '60s',
      preAllocatedVUs: Math.max(RATE * 2, 20), maxVUs: Math.max(RATE * 10, 200),
    },
  },
};

export default function () {
  const r = http.post(`${BASE}/auth/login`,
    JSON.stringify({ email: seedEmail(__ITER + __VU * 7919), password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login' } });
  loginDur.add(r.timings.duration);
  if (r.status === 200) acceptedDur.add(r.timings.duration);
  rejected.add(r.status === 429);
  loginOk.add(check(r, { 'login 200': (x) => x.status === 200 }));
}
