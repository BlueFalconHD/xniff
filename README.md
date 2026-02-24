# xniff

to use, build with

```
cmake --preset default -DXNIFF_ENABLE_ARM64E=ON
```

to run:

1) ensure SIP is disabled and your boot args look like:
```
-arm64e_preview_abi thid_should_crash=0 tss_should_crash=0 amfi_get_out_of_my_way=1
```

2) build
```
./build.sh
```

3) sniff a process (you might need to swap the path for an absolute one)
```
sudo build/xniff-cli sniff-xpc-wait com.apple.Virtualization.VirtualMachine build/libxniff-hooks.dylib --jsonl --xpc > out.json
```
