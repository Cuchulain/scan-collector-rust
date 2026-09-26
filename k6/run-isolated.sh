#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUST_REPO="$(cd -- "$SCRIPT_DIR/.." && pwd)"
GO_REPO="${GO_REPO:-"$RUST_REPO/../scan-collector"}"
RUN_ID="${RUN_ID:-"$(date +%Y%m%d%H%M%S)-$$"}"
IMAGE_SUFFIX="$(printf '%s' "$RUN_ID" | tr -c 'A-Za-z0-9_.-' '-')"
IMAGE_SUFFIX="${IMAGE_SUFFIX:0:40}"
if [[ -z "$IMAGE_SUFFIX" ]]; then
  IMAGE_SUFFIX="run-$$"
fi
RATE="${RATE:-10}"
DURATION="${DURATION:-1m}"
PREALLOCATED_VUS="${PREALLOCATED_VUS:-5}"
MAX_VUS="${MAX_VUS:-20}"
K6_SCRIPT="$SCRIPT_DIR/scan-ingest.js"
GO_IMAGE="scan-collector-k6-go:$IMAGE_SUFFIX"
RUST_IMAGE="scan-collector-k6-rust:$IMAGE_SUFFIX"
ACTIVE_CONTAINER=""
FAILURES=0

cleanup() {
  if [[ -n "$ACTIVE_CONTAINER" ]]; then
    docker rm --force "$ACTIVE_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in docker k6 curl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 2
  fi
done

if [[ ! -f "$GO_REPO/Dockerfile" ]]; then
  printf 'Go repository not found at %s; set GO_REPO to its path.\n' "$GO_REPO" >&2
  exit 2
fi

printf 'Building Go image from %s\n' "$GO_REPO"
docker build --tag "$GO_IMAGE" "$GO_REPO"
printf 'Building Rust image from %s\n' "$RUST_REPO"
docker build --tag "$RUST_IMAGE" "$RUST_REPO"

run_target() {
  local target="$1"
  local image="$2"
  local container="scan-k6-${target}-$$"
  local port_binding host_port status attempt response_code

  printf '\nStarting isolated %s test instance\n' "$target"
  ACTIVE_CONTAINER="$container"
  if ! docker run --detach --rm \
    --name "$container" \
    --label "scan-collector.k6.run=$RUN_ID" \
    --tmpfs /data:rw,nosuid,size=64m,uid=100,gid=100,mode=755 \
    --publish 127.0.0.1::8765 \
    --env AUTH_USER=k6-test \
    --env AUTH_PASSWORD=k6-test-only \
    "$image" >/dev/null; then
    ACTIVE_CONTAINER=""
    return 1
  fi

  if ! port_binding="$(docker port "$container" 8765/tcp | head -n 1)"; then
    docker rm --force "$container" >/dev/null 2>&1 || true
    ACTIVE_CONTAINER=""
    return 1
  fi
  host_port="${port_binding##*:}"

  for attempt in {1..60}; do
    response_code="$(curl --silent --output /dev/null --write-out '%{http_code}' \
      --connect-timeout 1 "http://127.0.0.1:$host_port/" || true)"
    if [[ -n "$response_code" && "$response_code" != "000" ]]; then
      break
    fi
    sleep 1
  done
  if [[ -z "${response_code:-}" || "$response_code" == "000" ]]; then
    printf '%s instance did not become ready.\n' "$target" >&2
    docker logs "$container" >&2 || true
    docker rm --force "$container" >/dev/null 2>&1 || true
    ACTIVE_CONTAINER=""
    return 1
  fi

  printf 'Running %s at http://127.0.0.1:%s (%s req/s for %s)\n' \
    "$target" "$host_port" "$RATE" "$DURATION"
  status=0
  BASE_URL="http://127.0.0.1:$host_port" \
    TARGET="$target" RUN_ID="$RUN_ID" RATE="$RATE" DURATION="$DURATION" \
    PREALLOCATED_VUS="$PREALLOCATED_VUS" MAX_VUS="$MAX_VUS" \
    k6 run "$K6_SCRIPT" || status=$?

  if ! docker rm --force "$container" >/dev/null; then
    return 1
  fi
  ACTIVE_CONTAINER=""
  if [[ "$status" -ne 0 ]]; then
    printf '%s k6 run failed (exit %s).\n' "$target" "$status" >&2
    return "$status"
  fi
}

if ! run_target go "$GO_IMAGE"; then
  FAILURES=$((FAILURES + 1))
fi
if ! run_target rust "$RUST_IMAGE"; then
  FAILURES=$((FAILURES + 1))
fi

if [[ "$FAILURES" -ne 0 ]]; then
  printf '\n%s target(s) failed.\n' "$FAILURES" >&2
  exit 1
fi

printf '\nBoth isolated load tests passed. Their /data tmpfs mounts were removed with the containers.\n'
