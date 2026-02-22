#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${ROOT}/build"

STRESS_BIN="${BUILD_DIR}/xniff-xpc-stress"
XNIFF_CLI="${BUILD_DIR}/xniff-cli"
HOOKS_DYLIB="${BUILD_DIR}/libxniff-hooks.dylib"

workers=6
threads=4
duration_s=15
min_ms=10
max_ms=250
sniff_count=1
out_dir=""
hooks_debug=0
full_capture=0

listener_flags=(--jsonl --no-dump --no-xpc)

usage() {
  cat <<EOF
Usage:
  $(basename "$0") [options]

Runs the XPC stress generator and automatically attaches xniff to worker PIDs,
writing per-target JSONL event streams to an output directory.

Options:
  --workers N        Number of worker processes (default: ${workers})
  --threads N        Sender threads per worker (default: ${threads})
  --duration S       Duration in seconds (default: ${duration_s})
  --min-ms MS        Min sleep between sends (default: ${min_ms})
  --max-ms MS        Max sleep between sends (default: ${max_ms})
  --sniff N          Number of workers to sniff (default: ${sniff_count}; use --sniff-all for all)
  --sniff-all        Sniff all workers
  --out DIR          Output directory (default: /tmp/xniff-xpc-harness-<timestamp>)
  --dump             Enable file dumps under /tmp/xniff/<pid> (disables --no-dump)
  --xpc              Enable Mach->XPC payload parsing (disables --no-xpc)
  --full-capture     Use xniff-hooks default capture sizes (can drop events under heavy traffic)
  --hooks-debug      Enable /tmp/xniff-hooks-<pid>.log in targets
  -h, --help         Show this help

Examples:
  $0 --workers 6 --threads 10 --duration 60 --min-ms 3 --max-ms 250 --sniff 1
  $0 --workers 6 --threads 10 --duration 60 --min-ms 3 --max-ms 250 --sniff-all --dump
EOF
}

die() { echo "error: $*" >&2; exit 2; }

remove_listener_flag() {
  local remove="$1"
  local next=()
  local f=""
  for f in "${listener_flags[@]}"; do
    if [[ "$f" == "$remove" ]]; then
      continue
    fi
    next+=("$f")
  done
  listener_flags=("${next[@]}")
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workers) workers="${2:-}"; shift 2 ;;
    --threads) threads="${2:-}"; shift 2 ;;
    --duration) duration_s="${2:-}"; shift 2 ;;
    --min-ms) min_ms="${2:-}"; shift 2 ;;
    --max-ms) max_ms="${2:-}"; shift 2 ;;
    --sniff) sniff_count="${2:-}"; shift 2 ;;
    --sniff-all) sniff_count="all"; shift 1 ;;
    --out) out_dir="${2:-}"; shift 2 ;;
    --dump)
      remove_listener_flag --no-dump
      shift 1
      ;;
    --xpc)
      remove_listener_flag --no-xpc
      shift 1
      ;;
    --full-capture) full_capture=1; shift 1 ;;
    --hooks-debug) hooks_debug=1; shift 1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -x "$STRESS_BIN" ]] || die "missing $STRESS_BIN (build first: cmake --build --preset default)"
[[ -x "$XNIFF_CLI" ]] || die "missing $XNIFF_CLI (build first: cmake --build --preset default)"
[[ -f "$HOOKS_DYLIB" ]] || die "missing $HOOKS_DYLIB (build first: cmake --build --preset default)"

if [[ -z "$out_dir" ]]; then
  ts="$(date +%Y%m%d-%H%M%S)"
  out_dir="/tmp/xniff-xpc-harness-${ts}"
fi
mkdir -p "$out_dir"

sniffer_pids=()
orch_pid=""

stop_sniffers() {
  for spid in "${sniffer_pids[@]:-}"; do
    pkill -TERM -P "$spid" 2>/dev/null || true
    kill -TERM "$spid" 2>/dev/null || true
  done
  sleep 0.2
  for spid in "${sniffer_pids[@]:-}"; do
    pkill -KILL -P "$spid" 2>/dev/null || true
    kill -KILL "$spid" 2>/dev/null || true
  done
}

cleanup() {
  stop_sniffers
  if [[ -n "${orch_pid}" ]]; then
    # Also terminate workers if we're interrupted early.
    pkill -TERM -P "${orch_pid}" 2>/dev/null || true
    kill -TERM "${orch_pid}" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

if [[ "$hooks_debug" -eq 1 ]]; then
  export XNIFF_HOOKS_DEBUG=1
fi

if [[ "$full_capture" -eq 0 ]]; then
  # Default to "stress-friendly" capture limits so the IPC stream doesn't get overwhelmed.
  # Override these in your environment or pass --full-capture.
  export XNIFF_MAX_MSG_COPY="${XNIFF_MAX_MSG_COPY:-1024}"
  export XNIFF_MAX_OOL_TOTAL="${XNIFF_MAX_OOL_TOTAL:-1}"
  export XNIFF_MAX_OOL_PER_DESC="${XNIFF_MAX_OOL_PER_DESC:-1}"
  export XNIFF_MAX_IPC_PAYLOAD="${XNIFF_MAX_IPC_PAYLOAD:-131072}"
fi

echo "starting stress: workers=${workers} threads=${threads} duration=${duration_s}s min=${min_ms}ms max=${max_ms}ms" >&2
"$STRESS_BIN" --run --workers "$workers" --threads "$threads" --duration "$duration_s" --min-ms "$min_ms" --max-ms "$max_ms" &
orch_pid="$!"

worker_pids=()
for _ in $(seq 1 100); do
  # bash 3.2 compatible: rely on word-splitting into array
  # shellcheck disable=SC2207
  worker_pids=( $(pgrep -P "$orch_pid" 2>/dev/null | sort -n || true) )
  if [[ "${#worker_pids[@]}" -ge "$workers" ]]; then
    break
  fi
  sleep 0.05
done

if [[ "${#worker_pids[@]}" -eq 0 ]]; then
  die "no workers found (orchestrator pid=${orch_pid})"
fi

if [[ "$sniff_count" == "all" ]]; then
  sniff_n="${#worker_pids[@]}"
else
  sniff_n="$sniff_count"
fi

if [[ "$sniff_n" -le 0 ]]; then die "--sniff must be >= 1"; fi
if [[ "$sniff_n" -gt "${#worker_pids[@]}" ]]; then sniff_n="${#worker_pids[@]}"; fi

echo "workers: ${worker_pids[*]} (orchestrator pid=${orch_pid})" >&2
echo "sniffing first ${sniff_n} worker(s) -> ${out_dir}" >&2

for ((i=0; i<sniff_n; i++)); do
  pid="${worker_pids[$i]}"
  out_jsonl="${out_dir}/xniff-${pid}.jsonl"
  out_err="${out_dir}/xniff-${pid}.err"
  echo "sniff pid=${pid} -> ${out_jsonl}" >&2
  "$XNIFF_CLI" sniff-xpc "$pid" "$HOOKS_DYLIB" "${listener_flags[@]}" >"$out_jsonl" 2>"$out_err" &
  sniffer_pids+=("$!")
done

wait "$orch_pid" || true
stop_sniffers
trap - INT TERM EXIT

total=0
for ((i=0; i<sniff_n; i++)); do
  pid="${worker_pids[$i]}"
  out_jsonl="${out_dir}/xniff-${pid}.jsonl"
  lines="$(wc -l < "$out_jsonl" 2>/dev/null || echo 0)"
  echo "pid ${pid}: ${lines} events (${out_jsonl})" >&2
  total=$((total + lines))
done
echo "done: total_events=${total} out=${out_dir}" >&2
