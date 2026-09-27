// /mypage 캐시 실험 공통 하네스.
// constant-arrival-rate(고정 유입률)로 A(기존 SQL)/B(튜닝)/C(+Redis)를 같은 조건으로 비교한다.
// 반복당 HTTP 1건 → 설정 rate가 곧 요청 RPS. 토큰 풀을 미리 발급해 로그인 비용을 배제한다.
import { check } from 'k6';
import http from 'k6/http';
import { Trend, Rate as RateMetric } from 'k6/metrics';
import { BASE, PASSWORD, seedEmail } from './common.js';

const RATE = parseInt(__ENV.RATE || '100', 10);     // 목표 RPS
const DURATION = __ENV.DURATION || '3m';
const POOL = parseInt(__ENV.POOL_USERS || '100', 10);
const DIST = __ENV.DIST || 'hot';                   // hot | wide
const HOT_FRACTION = 0.2;                            // 상위 20% 사용자
const HOT_SHARE = 0.8;                               // 요청의 80%

const mypageDur = new Trend('mypage_duration', true);
const okRate = new RateMetric('mypage_ok');

export const options = {
  insecureSkipTLSVerify: true,
  scenarios: {
    fixed: {
      executor: 'constant-arrival-rate',
      rate: RATE, timeUnit: '1s', duration: DURATION,
      preAllocatedVUs: Math.max(RATE, 50), maxVUs: Math.max(RATE * 4, 200),
    },
  },
};

export function setup() {
  const tokens = [];
  for (let i = 0; i < POOL; i++) {
    const r = http.post(`${BASE}/auth/login`,
      JSON.stringify({ email: seedEmail(i), password: PASSWORD }),
      { headers: { 'Content-Type': 'application/json' } });
    tokens.push(r.status === 200 ? r.json('accessToken') : null);
  }
  return { tokens: tokens.filter(Boolean) };
}

function pickIndex(n) {
  if (DIST === 'wide') return Math.floor(Math.random() * n);
  const hotCount = Math.max(1, Math.floor(n * HOT_FRACTION));
  if (Math.random() < HOT_SHARE) return Math.floor(Math.random() * hotCount);
  return hotCount + Math.floor(Math.random() * (n - hotCount));
}

export default function (data) {
  const t = data.tokens[pickIndex(data.tokens.length)];
  const r = http.get(`${BASE}/mypage`,
    { headers: { Authorization: `Bearer ${t}` }, tags: { name: 'mypage' } });
  mypageDur.add(r.timings.duration);
  const ok = check(r, { 'mypage 200': (res) => res.status === 200 });
  okRate.add(ok);
}
