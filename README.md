# xniff

`xniff` captures Mach or high-level XPC traffic from a process and writes a
compact dump that can be explored in the native viewer.

## Build

xniff currently targets Apple silicon macOS. Disable SIP and use the required
boot arguments before capturing protected processes:

```text
-arm64e_preview_abi thid_should_crash=0 tss_should_crash=0 amfi_get_out_of_my_way=1
```

Build the capture CLI, its embedded hooks, and the viewer:

```sh
./build.sh
```

## Capture

There are two commands: `launch` starts a process with hooks installed before
`main`, while `attach` injects the same hooks into an existing PID.

Launch a process and capture high-level XPC traffic:

```sh
sudo build/xniff-cli launch --xpc --out /tmp/screentime.xniff -- \
  /System/Library/PrivateFrameworks/ScreenTimeCore.framework/screentimediagnose \
  inspect --verbose
```

Attach to an existing process and capture Mach messages:

```sh
sudo build/xniff-cli attach 1234 --mach --out /tmp/process.xniff
```

Use `--xpc` for decoded high-level requests, responses, incoming messages, and
one-way sends. Use `--mach` for the lower-level message and descriptor stream.
The hooks dylib is embedded in `xniff-cli`; `--hooks /path/to/hooks.dylib` is
only a development override.

Without `--out`, xniff prints events as they arrive. Run
`build/xniff-cli --help` for the complete interface.

## Viewer

Open a dump directly:

```sh
build/xniff-viewer /tmp/screentime.xniff
```

The build also produces `build/xniff-viewer.app` for Finder or Launchpad-style
use. Dumps with `.xniff` and `.xniffbin` extensions can be opened with the app.

The native SwiftUI/AppKit viewer memory-maps and indexes the dump, filters large
traces off the main thread, and decodes payloads only when selected. It groups
XPC requests and responses by call ID and recursively expands libxpc v5 values,
property lists, JSON data, and `NSKeyedArchiver` objects without loading the
application's private classes.

For terminal inspection, use:

```sh
python3 scripts/print_xpc.py /tmp/screentime.xniff
```
