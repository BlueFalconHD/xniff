# XPC Stress Harness

`xniff-xpc-stress` is a multi-process, multi-threaded XPC traffic generator intended to reproduce crashes and validate xniff under heavy XPC activity.

## Build

```
cmake --preset default
cmake --build --preset default
```

## Run

From the repo root:

```
./build/xniff-xpc-stress --run --workers 6 --threads 4 --duration 15 --min-ms 10 --max-ms 250
```

This mode:

- Creates a temporary per-user `launchd` job (Mach service) used only as a rendezvous server to exchange anonymous XPC listener endpoints.
- Spawns `--workers` copies of `xniff-xpc-stress`, each with `--threads` sender threads.
- Workers send nested dictionaries/arrays + large `xpc_data` blobs (often OOL) and sometimes FDs, at random intervals.

Note: the PID of the `--run` process is just the orchestrator. For meaningful XPC traffic, sniff one of its worker PIDs (children).

## Full harness (recommended)

This runs the stress generator, finds the worker PIDs, attaches `xniff-cli`, and writes per-target JSONL files:

```
./scripts/xpc_stress_harness.sh --workers 6 --threads 10 --duration 60 --min-ms 3 --max-ms 250 --sniff 1
```

Output is written under `/tmp/xniff-xpc-harness-<timestamp>/` by default.

If you want the default (larger) capture sizes from `xniff-hooks`, pass `--full-capture` (may drop events under very heavy traffic).

## Manual sniff (one worker)

1) Run the stress orchestrator in one terminal:

```
./build/xniff-xpc-stress --run --workers 6 --threads 10 --duration 60 --min-ms 3 --max-ms 250
```

2) In another terminal, get a worker PID (child of the orchestrator PID) and attach:

```
pgrep -P <orchestrator_pid>
./build/xniff-cli sniff-xpc <worker_pid> ./build/libxniff-hooks.dylib --jsonl --no-dump --no-xpc > /tmp/xniff-events.jsonl
```

Press Ctrl-C to stop `xniff-cli`.

Server logs are written to:

- `/tmp/xniff-xpc-stress-server.out`
- `/tmp/xniff-xpc-stress-server.err`

## Tuning xniff-hooks limits

The injected `xniff-hooks` dylib now enforces conservative per-event limits to avoid crashing targets on malformed/partial messages. Override if needed:

- `XNIFF_MAX_MSG_COPY` (default: 256 KiB)
- `XNIFF_MAX_OOL_TOTAL` (default: 1 MiB)
- `XNIFF_MAX_OOL_PER_DESC` (default: 256 KiB)
- `XNIFF_MAX_DESCRIPTORS` (default: 64)
- `XNIFF_MAX_IPC_PAYLOAD` (default: 4 MiB)

You can also tune the IPC send timeout used by instrumented targets:

- `XNIFF_IPC_SNDTIMEO_MS` (default: 50)
