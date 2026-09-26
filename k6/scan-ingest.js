import http from 'k6/http';
import { check } from 'k6';

const baseUrl = (__ENV.BASE_URL || '').replace(/\/$/, '');
const target = __ENV.TARGET || 'scan-collector';
const runId = __ENV.RUN_ID || String(Date.now());
const rate = Number(__ENV.RATE || 10);
const duration = __ENV.DURATION || '1m';
const preAllocatedVUs = Number(__ENV.PREALLOCATED_VUS || 5);
const maxVUs = Number(__ENV.MAX_VUS || 20);

if (!baseUrl) {
  throw new Error('Set BASE_URL, for example http://localhost:8765');
}
if (!Number.isInteger(rate) || rate < 1) {
  throw new Error('RATE must be a positive integer (iterations per second)');
}

export const options = {
  scenarios: {
    scan_ingest: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs,
      maxVUs,
      tags: { target },
    },
  },
  thresholds: {
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<1000'],
    dropped_iterations: ['count==0'],
  },
};

export default function () {
  const payload = {
    timestamp: new Date().toISOString(),
    content: `k6-${target}-${runId}-vu${__VU}-iter${__ITER}`,
    format: 'QR_CODE',
    deviceId: `k6-${target}-vu${__VU}`,
  };

  const response = http.post(`${baseUrl}/`, JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
    tags: { endpoint: 'scan-post', target },
  });

  check(response, {
    'scan POST returns 200': (res) => res.status === 200,
    'scan POST returns OK': (res) => res.body === 'OK',
  });
}
