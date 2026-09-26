# k6 scan ingest load test

`scan-ingest.js` exercises the shared, unauthenticated `POST /` scan endpoint
in both `cuchulain/scan-collector` (Go) and
`cuchulain/scan-collector-rust` (Rust). It writes synthetic rows to the
target's daily CSV file; use a test instance with disposable data, not a
production instance.

Run the same test against each server separately so the results do not affect
each other's latency:

```sh
BASE_URL=http://localhost:8765 TARGET=go k6 run k6/scan-ingest.js
BASE_URL=http://localhost:8766 TARGET=rust k6 run k6/scan-ingest.js
```

Defaults are 10 requests per second for one minute, with 5 preallocated VUs
and at most 20 VUs. Override them with `RATE` (iterations per second),
`DURATION`, `PREALLOCATED_VUS`, and `MAX_VUS`. For example, a short smoke run:

```sh
BASE_URL=http://localhost:8765 TARGET=go RATE=1 DURATION=15s k6 run k6/scan-ingest.js
```

Each request has a unique synthetic content value (override `RUN_ID` when
you need to label or distinguish a run). The test fails if more than
1% of requests fail, fewer than 99% of checks pass, p95 latency reaches one
second, or k6 drops an iteration. Treat those as initial comparison thresholds;
adjust them to the load generator and service-level objectives before using
them as release gates.

With the Go Compose service, publish a different host port (for example,
`PORT=8765`) and use another for Rust (for example, `PORT=8766`) so both can be
running at once. Alternatively, stop one service before starting the other.
