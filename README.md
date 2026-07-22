# xniff

`xniff` sniffs xpc or mach IPC communications going to and from a target process.

## boot args

xniff is made for apple silicon, and likely requires the following boot args to be set in order to run
properly.

```text
-arm64e_preview_abi thid_should_crash=0 tss_should_crash=0 amfi_get_out_of_my_way=1
```

## building xniff

to build xniff, use the shell script

```sh
./build.sh
```

## capturing traffic

xniff supports capturing traffic from both newly created and preexisting
processes.

newly created processes:

```sh
sudo build/xniff launch --xpc --out /tmp/out.xniff -- /usr/bin/shortcuts list
```

Status output is grouped by short labels so the capture lifecycle stays easy to
scan:

```text
launch   shortcuts (pid 30308)
capture  XPC events → /tmp/out.xniff
ready    listening to pid 30308, press Ctrl-C to stop
done     shortcuts exited successfully
```

Color is enabled automatically when status output is connected to a terminal.
Set `XNIFF_COLOR=never`, `XNIFF_COLOR=0`, `NO_COLOR=1`, or `CLICOLOR=0` to
disable it. `XNIFF_COLOR=always`, `CLICOLOR_FORCE=1`, and `FORCE_COLOR=1` force
color when output is redirected. Set `XNIFF_VERBOSE=1` to include internal hook,
listener, and transport details.

existing processes:

```sh
sudo build/xniff attach 1234 --mach --out /tmp/process.xniff
```

## reading dumps

xniff has both a graphical and command line interface to interact with captured dumps.

to open a dump in the viewer:

```sh
build/xniff-viewer /tmp/screentime.xniff
```

to view in the terminal:

```sh
build/xniff-print /tmp/out.xniff
```
