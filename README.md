# Scan Collector Rust

Rust implementation of Scan Collector for Binary Eye. It accepts JSON scan records and appends them to daily CSV files. The authenticated dashboard lists daily sets, shows their records, and downloads original CSV files.

## Run with Docker Compose

Copy `.env.example` to `.env`, set a unique password, then start the service:

```sh
cp .env.example .env
docker compose up -d
```

The dashboard is at `http://localhost:8765/`. Set `COOKIE_SECURE=true` when serving it through HTTPS. Configure TLS at a reverse proxy before exposing the service publicly.

`AUTH_USER` and `AUTH_PASSWORD` configure the login. `SESSION_TTL` sets normal session duration (default `8h`); `SESSION_EXTENDED_TTL` sets the duration selected by the login checkbox (default `720h`, 30 days). Values use duration syntax such as `12h` or `14d`. Sessions are stored in `/data/sessions.sqlite3`, so they survive container restarts along with CSV data. The cookie contains an opaque random token; only its SHA-256 hash is stored in SQLite.

The app listens on container port `8765`; `PORT` changes the published host port. The data volume contains `scan-YYYY-MM-DD.csv` files and `sessions.sqlite3`. At startup, the container assigns the mounted `/data` directory to its unprivileged `app` user, then runs the server as that user. Keep `./data` dedicated to this app because existing files in that directory have their ownership changed on startup.

## API

Unauthenticated scan submission is supported at `POST /`:

```sh
curl -X POST http://localhost:8765/ \
  -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-09-25T12:00:00Z","content":"sample scanned data","format":"QR_CODE","deviceId":"scanner-1"}'
```

The web interface requires login. CSV columns are `čas,obsah,formát,zařízení`.

## Development

```sh
cargo run
cargo test
```

Set `AUTH_USER` and `AUTH_PASSWORD` before running locally. `DATA_DIR` defaults to `/data`; set it to a writable local path for development.

## Load testing

See [`k6/README.md`](k6/README.md) for a reusable k6 scan-ingest load test that targets either the Go or Rust server.
