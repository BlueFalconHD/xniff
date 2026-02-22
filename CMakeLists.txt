cmake_minimum_required(VERSION 3.20)

project(xniff VERSION 0.1.0 LANGUAGES C ASM)

# Force arm64 build on macOS to assemble AArch64 trampolines
if(APPLE)
    if(NOT CMAKE_OSX_ARCHITECTURES)
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
    endif()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(XNIFF_FRIDA_GUM_VERSION "16.5.6" CACHE STRING "Frida Gum devkit version")
option(XNIFF_ENABLE_ARM64E "Download arm64e Frida Gum devkit and build arm64e xniff-hooks" OFF)

# Always use Frida Gum for in-process interception (no custom patcher fallback).
include(FetchContent)
if(APPLE)
    if(XNIFF_ENABLE_ARM64E)
        set(_frida_gum_arch "arm64e")
    else()
        set(_frida_gum_arch "arm64")
    endif()
    set(_frida_gum_url "https://github.com/frida/frida/releases/download/${XNIFF_FRIDA_GUM_VERSION}/frida-gum-devkit-${XNIFF_FRIDA_GUM_VERSION}-macos-${_frida_gum_arch}.tar.xz")
else()
    message(FATAL_ERROR "xniff-hooks currently supports Frida Gum only on macOS arm64/arm64e")
endif()

FetchContent_Declare(frida_gum_devkit URL "${_frida_gum_url}")
FetchContent_MakeAvailable(frida_gum_devkit)

add_library(frida-gum STATIC IMPORTED GLOBAL)
set_target_properties(frida-gum PROPERTIES
    IMPORTED_LOCATION "${frida_gum_devkit_SOURCE_DIR}/libfrida-gum.a"
    INTERFACE_INCLUDE_DIRECTORIES "${frida_gum_devkit_SOURCE_DIR}"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

file(GLOB XNIFF_LIB_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/libxniff/src/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/libxniff/src/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/libxniff/src/*.S"
)

add_library(xniff SHARED ${XNIFF_LIB_SOURCES})
target_include_directories(xniff
    PUBLIC
        ${PROJECT_SOURCE_DIR}/Sources/libxniff/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/Sources/libxniff/src
)

set_target_properties(xniff PROPERTIES
    OUTPUT_NAME xniff
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

## Removed: xniff-rt runtime dylib target
## (former target and sources under Sources/xniff-rt)

# Hooks dylib with Mach message entry/exit hooks (XPC sniffing)
file(GLOB XNIFF_HOOKS_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-hooks/*.c"
)
if(XNIFF_HOOKS_SOURCES)
    add_library(xniff-hooks SHARED ${XNIFF_HOOKS_SOURCES} ${PROJECT_SOURCE_DIR}/Sources/shared/xniff_ipc.c)
    target_include_directories(xniff-hooks PUBLIC 
        ${PROJECT_SOURCE_DIR}/Sources/xniff-hooks 
        ${PROJECT_SOURCE_DIR}/Sources/shared)
    target_compile_options(xniff-hooks PRIVATE -fvisibility=hidden)
    if(APPLE)
        # libxpc is commonly provided via the dyld shared cache and may not be linkable
        # as a standalone library in all SDK/runtime setups. Allow unresolved xpc_*
        # symbols and resolve them at load time in the target process.
        target_link_options(xniff-hooks PRIVATE "-Wl,-undefined,dynamic_lookup")
    endif()
    target_link_libraries(xniff-hooks PRIVATE frida-gum resolv m)
    set_target_properties(xniff-hooks PROPERTIES OUTPUT_NAME xniff-hooks)
    if(APPLE AND XNIFF_ENABLE_ARM64E)
        set_target_properties(xniff-hooks PROPERTIES OSX_ARCHITECTURES "arm64e")
    endif()
endif()

file(GLOB XNIFF_CLI_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.S"
)

add_executable(xniff-cli ${XNIFF_CLI_SOURCES} ${PROJECT_SOURCE_DIR}/Sources/shared/xniff_ipc.c)
target_link_libraries(xniff-cli PRIVATE xniff xpcdesert)
target_include_directories(xniff-cli PRIVATE 
    ${PROJECT_SOURCE_DIR}/Sources/libxniff/include
    ${PROJECT_SOURCE_DIR}/Sources/shared
    ${PROJECT_SOURCE_DIR}/Sources/xpcdesert)

file(GLOB XNIFF_TEST_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-tests/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-tests/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-tests/*.S"
)

add_executable(xniff-test ${XNIFF_TEST_SOURCES} ${PROJECT_SOURCE_DIR}/Sources/shared/xniff_ipc.c)
target_link_libraries(xniff-test PRIVATE)
target_include_directories(xniff-test PRIVATE
    ${PROJECT_SOURCE_DIR}/Sources/shared)

# XPC stress harness (multi-process, multi-threaded)
file(GLOB XNIFF_XPC_STRESS_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-xpc-stress/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-xpc-stress/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-xpc-stress/*.S"
)
add_executable(xniff-xpc-stress ${XNIFF_XPC_STRESS_SOURCES})
target_compile_options(xniff-xpc-stress PRIVATE -fblocks)

# xpcdesert shared library + CLI
set(XPCDESERT_DIR "${PROJECT_SOURCE_DIR}/Sources/xpcdesert")
set(XPCDESERT_LIB_SOURCES
    "${XPCDESERT_DIR}/xpcdesert.c"
    "${XPCDESERT_DIR}/stream.c"
)
add_library(xpcdesert SHARED ${XPCDESERT_LIB_SOURCES})
target_include_directories(xpcdesert PUBLIC ${XPCDESERT_DIR})
set_target_properties(xpcdesert PROPERTIES OUTPUT_NAME xpcdesert)

# CLI builds on the same sources as before but now links against the library
add_executable(xpcdesert-cli "${XPCDESERT_DIR}/xpcdesert_cli.c")
target_include_directories(xpcdesert-cli PRIVATE ${XPCDESERT_DIR})
target_link_libraries(xpcdesert-cli PRIVATE xpcdesert xniff)

# macOS codesigning with JIT entitlements (for testing self-modifying code)
if(APPLE)
    set(XNIFF_ENTITLEMENTS "${PROJECT_SOURCE_DIR}/macos.entitlements.plist")
    if(EXISTS "${XNIFF_ENTITLEMENTS}")
        add_custom_command(TARGET xniff POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff>"
            COMMENT "Codesigning libxniff with JIT entitlements")

        ## Removed codesign step for xniff-rt (runtime dylib)

        if(TARGET xniff-hooks)
            add_custom_command(TARGET xniff-hooks POST_BUILD
                COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-hooks>"
                COMMENT "Codesigning xniff-hooks with JIT entitlements")
        endif()

        add_custom_command(TARGET xniff-test POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-test>"
            COMMENT "Codesigning xniff-test with JIT entitlements")

        add_custom_command(TARGET xniff-cli POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-cli>"
            COMMENT "Codesigning xniff-cli with JIT entitlements")

        add_custom_command(TARGET xniff-xpc-stress POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-xpc-stress>"
            COMMENT "Codesigning xniff-xpc-stress with JIT entitlements")

        if(TARGET xpcdesert)
            add_custom_command(TARGET xpcdesert POST_BUILD
                COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xpcdesert>"
                COMMENT "Codesigning xpcdesert (lib) with JIT entitlements")
        endif()
        if(TARGET xpcdesert-cli)
            add_custom_command(TARGET xpcdesert-cli POST_BUILD
                COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xpcdesert-cli>"
                COMMENT "Codesigning xpcdesert-cli with JIT entitlements")
        endif()
    else()
        message(WARNING "macos.entitlements.plist not found; binaries will not be codesigned.")
    endif()
endif()
