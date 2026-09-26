import http from 'k6/http';
import { check } from 'k6';

// 로컬 secure 대상만. seed 사용자 공용 비밀번호.
export const BASE = __ENV.BASE || 'https://127.0.0.1:8443';
export const PASSWORD = __ENV.SEED_PASSWORD || 'loadtest-pw-1234';
export const USER_COUNT = parseInt(__ENV.USER_COUNT || '500', 10);

// TLS는 로컬 self-signed. 부하 측정이 목적이라 검증을 끈다(로컬 전용).
export const tlsOption = { insecureSkipTLSVerify: true };

export function seedEmail(i) {
  const n = String((i % USER_COUNT) + 1).padStart(3, '0');
  return `user${n}@zetty.test`;
}

export function login(email) {
  const res = http.post(`${BASE}/auth/login`, JSON.stringify({ email, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' }, tags: { name: 'login' } });
  check(res, { 'login 200': (r) => r.status === 200 });
  if (res.status !== 200) return null;
  try { return res.json('accessToken'); } catch (e) { return null; }
}

export function authGet(path, token, name) {
  return http.get(`${BASE}${path}`,
    { headers: { Authorization: `Bearer ${token}` }, tags: { name } });
}
