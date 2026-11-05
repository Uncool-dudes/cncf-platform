// Fixed-arrival-rate GET load over a list of in-cluster URLs. Keep targets
// read-only: only the request path (sidecars, CNI, Falco syscall tracing)
// should differ between benchmarked layers.
import http from 'k6/http';
import { check } from 'k6';

// targets.json: ["http://svc.ns.svc.cluster.local:port/path", ...]
const targets = JSON.parse(open('/scripts/targets.json'));

export const options = {
  scenarios: {
    steady: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '3m',
      preAllocatedVUs: 20,
      maxVUs: 100,
    },
  },
  summaryTrendStats: ['avg', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

export default function () {
  const url = targets[Math.floor(Math.random() * targets.length)];
  const res = http.get(url, { tags: { target: url } });
  check(res, { 'status 200': (r) => r.status === 200 });
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
