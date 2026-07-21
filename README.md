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
traces off the main thread, and decodes payloads only when selected. Each row is
one logical call; its request and response share a bottom inspector with
Headers, Backtrace, Body, and Hex tabs.

Body is the default view. It recursively expands libxpc v5 values, binary/XML
property lists, JSON, `NSKeyedArchiver`, and the inline `bplist17` format used by
Foundation XPC without loading the target application's private classes. Keyed
archives retain their encoded class names and property keys in the tree.

The Body inspector picker shows every analysis layer that applies to the
selected payload, with the most semantic layer selected by default. The built-in
layers are **Raw XPC**, **Foundation NSXPC**, and **Core Data**. Foundation hides
the `f`, `root`, `proxynum`, `replysig`, and `sequence` transport envelope; Core
Data then hides `NSCoreDataXPCMessage` and its nested archive framing. You can
select a lower layer at any time to audit that transformation. Private Core Data
result buffers whose format is not yet understood are labeled as opaque rather
than presented as a successful decode.

Right-click any decoded tree item and choose **Show in Hex** to jump to its bytes
in the original serialized XPC message. See [Viewer/INSPECTORS.md](Viewer/INSPECTORS.md)
for the small API used to add another layered body inspector.

For terminal inspection, use:

```sh
python3 scripts/print_xpc.py /tmp/screentime.xniff
```
