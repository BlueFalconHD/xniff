# Building xniff

## Prerequisites

- CMake 3.20 or newer
- A C11-compatible compiler (for example, `clang` or `gcc`)

## Configure

From the repository root, configure the build into `./build`:

```
cmake --preset default
```

`xniff-hooks` statically links Frida Gum (downloaded as a devkit during configure).

This generates the build tree and a `compile_commands.json` database under `build/` for editor tooling.

## Build

After configuration, build all targets:

```
cmake --build --preset default
```

Artifacts are produced in the `build/` directory:

- `libxniff.dylib` – shared library
- `xniff-cli` – command-line interface
- `xniff-test` – lightweight test executable
- `xniff-xpc-stress` – multi-process XPC stress harness

## Running the executables

Both executables can be run directly from the `build/` directory once built:

```
./build/xniff-cli
./build/xniff-test
./build/xniff-xpc-stress --help
```
