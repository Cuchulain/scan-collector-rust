# k6 scan ingest load test

`scan-ingest.js` exercises the shared, unauthenticated `POST /` scan endpoint
in both `cuchulain/scan-collector` (Go) and
`cuchulain/scan-collector-rust` (Rust). The runner below builds both images,
starts isolated containers one at a time, runs k6, and removes each container
afterward. Each container stores records in a 64 MB in-memory `/data` tmpfs;
removing the container removes the test CSV and SQLite files without touching
either repository's normal `data/` directory.

From the Rust repository root, with Docker and k6 installed and the Go
repository at `../scan-collector`, run:

```sh
./k6/run-isolated.sh
```

Set `GO_REPO` if the Go checkout is elsewhere. The script attempts both
targets even if one k6 run fails and returns a failing exit status if either
does. Temporary image tags use a per-run identifier and remain in the local
Docker image cache; the test containers and their data are removed.

To start only one project manually and target it with k6:

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
