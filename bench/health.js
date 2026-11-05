// Fixed-arrival-rate load over a list of in-cluster targets. Keep targets
// stateless: only the request path (sidecars, CNI, Falco syscall tracing)
// should differ between benchmarked layers.
import http from 'k6/http';
import { check } from 'k6';

// targets.json entries: "http://svc.ns.svc.cluster.local:port/path" for a GET,
// or {"url": ..., "method": "POST", "body": ...}.
const targets = JSON.parse(open('/scripts/targets.json')).map((t) =>
  typeof t === 'string' ? { url: t, method: 'GET', body: null } : { method: 'GET', body: null, ...t });

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: Number(__ENV.RATE || 50),
      timeUnit: '1s',
      duration: __ENV.DURATION || '3m',
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const t = targets[Math.floor(Math.random() * targets.length)];
  const res = http.request(t.method, t.url, t.body, { tags: { target: t.url } });
  check(res, { 'status 2xx': (r) => r.status >= 200 && r.status < 300 });
}

export function handleSummary(data) {
  const d = data.metrics.http_req_duration.values;
  const summary = {
    label: __ENV.LABEL,
    requests: data.metrics.http_reqs.values.count,
    failed_rate: data.metrics.http_req_failed.values.rate,
    latency_ms: { avg: d.avg, p50: d.med, p90: d['p(90)'], p95: d['p(95)'], p99: d['p(99)'], max: d.max },
  };
  return { stdout: `BENCH_SUMMARY ${JSON.stringify(summary)}\n` };
}
