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

