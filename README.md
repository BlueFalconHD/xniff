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
sudo build/xniff-cli launch --xpc --out /tmp/out.xniff -- /usr/bin/shortcuts list
```

existing processes:

```sh
sudo build/xniff-cli attach 1234 --mach --out /tmp/process.xniff
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
