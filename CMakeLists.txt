cmake_minimum_required(VERSION 3.20)

project(xniff VERSION 0.1.0 LANGUAGES C ASM)
enable_testing()

if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

set(XNIFF_FRIDA_GUM_VERSION "16.5.6" CACHE STRING "Frida Gum devkit version")
option(XNIFF_ENABLE_ARM64E "Build the capture tools for arm64e" OFF)

function(xniff_enable_arm64e target_name)
    if(APPLE AND XNIFF_ENABLE_ARM64E)
        set_target_properties(${target_name} PROPERTIES OSX_ARCHITECTURES "arm64e")
    endif()
endfunction()

if(NOT APPLE)
    message(FATAL_ERROR "xniff currently supports macOS only")
endif()

include(FetchContent)
if(XNIFF_ENABLE_ARM64E)
    set(XNIFF_FRIDA_GUM_ARCH "arm64e")
    set(XNIFF_FRIDA_GUM_SHA256 "dddb8ed3a699ea48533eaa46bb014d2252460d7ac21213f91d239cc93263919c")
else()
    set(XNIFF_FRIDA_GUM_ARCH "arm64")
    set(XNIFF_FRIDA_GUM_SHA256 "0feeca0f94c5cf4274285e646ba8e02b593aa644926b3a0a1bd18290955c8870")
endif()
set(XNIFF_FRIDA_GUM_URL
    "https://github.com/frida/frida/releases/download/${XNIFF_FRIDA_GUM_VERSION}/frida-gum-devkit-${XNIFF_FRIDA_GUM_VERSION}-macos-${XNIFF_FRIDA_GUM_ARCH}.tar.xz")
FetchContent_Declare(frida_gum_devkit
    URL "${XNIFF_FRIDA_GUM_URL}"
    URL_HASH "SHA256=${XNIFF_FRIDA_GUM_SHA256}"
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(frida_gum_devkit)

add_library(frida-gum STATIC IMPORTED GLOBAL)
set_target_properties(frida-gum PROPERTIES
    IMPORTED_LOCATION "${frida_gum_devkit_SOURCE_DIR}/libfrida-gum.a"
    INTERFACE_INCLUDE_DIRECTORIES "${frida_gum_devkit_SOURCE_DIR}")

add_library(xniff-record STATIC Sources/shared/xniff_record.c)
target_include_directories(xniff-record PUBLIC Sources/shared)
set_target_properties(xniff-record PROPERTIES POSITION_INDEPENDENT_CODE ON)
xniff_enable_arm64e(xniff-record)

add_library(xniff-transport STATIC Sources/shared/xniff_transport.c)
target_include_directories(xniff-transport PUBLIC Sources/shared)
set_target_properties(xniff-transport PROPERTIES POSITION_INDEPENDENT_CODE ON)
xniff_enable_arm64e(xniff-transport)

add_library(xniff-injector STATIC
    Sources/xniff-injector/src/dylib_inject_stub.S
    Sources/xniff-injector/src/inject.c
    Sources/xniff-injector/src/macho_symbols.c
    Sources/xniff-injector/src/patch.c)
target_include_directories(xniff-injector PUBLIC Sources/xniff-injector/include)
xniff_enable_arm64e(xniff-injector)

add_library(xniff-hook-state STATIC
    Sources/xniff-hooks/xpc_reply_tracker.c
    Sources/xniff-hooks/xpc_session_coalescer.c)
target_include_directories(xniff-hook-state PUBLIC Sources/xniff-hooks)
set_target_properties(xniff-hook-state PROPERTIES POSITION_INDEPENDENT_CODE ON)
xniff_enable_arm64e(xniff-hook-state)

add_library(xniff-hooks SHARED
    Sources/xniff-hooks/frida_gum_interceptor.c
    Sources/xniff-hooks/xniff_hooks_api.c
    Sources/xniff-hooks/xniff_hooks_backtrace.c
    Sources/xniff-hooks/xniff_hooks_runtime.c
    Sources/xniff-hooks/xpc_highlevel_hooks.c
    Sources/xniff-hooks/xpc_hooks.c)
target_include_directories(xniff-hooks PRIVATE Sources/xniff-hooks)
target_compile_options(xniff-hooks PRIVATE -fvisibility=hidden -fblocks)
target_link_options(xniff-hooks PRIVATE "-Wl,-undefined,dynamic_lookup")
target_link_libraries(xniff-hooks PRIVATE
    frida-gum
    xniff-hook-state
    xniff-record
    xniff-transport
    resolv
    m)
set_target_properties(xniff-hooks PROPERTIES OUTPUT_NAME xniff-hooks)
xniff_enable_arm64e(xniff-hooks)

add_library(xniff-cli-support STATIC
    Sources/xniff-cli/cli_options.c
    Sources/xniff-cli/launch_environment.c
    Sources/xniff-cli/shared_transport.c
    Sources/xniff-cli/target_identity.c)
target_include_directories(xniff-cli-support PUBLIC Sources/xniff-cli)
target_link_libraries(xniff-cli-support PUBLIC xniff-injector xniff-transport)
xniff_enable_arm64e(xniff-cli-support)

add_executable(xniff-cli
    Sources/xniff-cli/capture.c
    Sources/xniff-cli/embedded_hooks.c
    Sources/xniff-cli/mach_record_renderer.c
    Sources/xniff-cli/main.c
    Sources/xniff-cli/process_control.c
    Sources/xniff-cli/record_renderer.c
    Sources/xniff-cli/record_render_support.c
    Sources/xniff-cli/xpc_record_renderer.c)
target_link_libraries(xniff-cli PRIVATE xniff-cli-support xniff-record)
xniff_enable_arm64e(xniff-cli)
add_dependencies(xniff-cli xniff-hooks)
set_property(TARGET xniff-cli APPEND PROPERTY LINK_DEPENDS "$<TARGET_FILE:xniff-hooks>")
target_link_options(xniff-cli PRIVATE
    "LINKER:-sectcreate,__DATA,__xniff_hooks,$<TARGET_FILE:xniff-hooks>")

add_executable(xniff-test
    Sources/xniff-tests/main.c
    Sources/xniff-tests/shared_transport_test.c
    Sources/xniff-tests/target_user_test.c
    Sources/xniff-tests/xpc_session_coalescer_test.c)
target_link_libraries(xniff-test PRIVATE
    xniff-cli-support
    xniff-hook-state
    xniff-record)
xniff_enable_arm64e(xniff-test)

add_test(NAME xniff-transport-ring COMMAND xniff-test --transport-ring)
add_test(NAME xniff-transport-drop COMMAND xniff-test --transport-drop)
add_test(NAME xniff-record-call-id COMMAND xniff-test --record-call-id)
add_test(NAME xniff-shared-transport-tail COMMAND xniff-test --shared-transport-tail)
add_test(NAME xniff-xpc-reply-tracker COMMAND xniff-test --xpc-reply-tracker)
add_test(NAME xniff-xpc-session-coalescer COMMAND xniff-test --xpc-session-coalescer)
add_test(NAME xniff-target-user-options COMMAND xniff-test --target-user-options)
add_test(NAME xniff-target-identity COMMAND xniff-test --target-identity)

set(XNIFF_ENTITLEMENTS "${PROJECT_SOURCE_DIR}/macos.entitlements.plist")
function(xniff_codesign target_name)
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND codesign --force -s - --options runtime
                --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:${target_name}>"
        COMMENT "Codesigning ${target_name}")
endfunction()

if(EXISTS "${XNIFF_ENTITLEMENTS}")
    xniff_codesign(xniff-hooks)
    xniff_codesign(xniff-cli)
else()
    message(WARNING "macos.entitlements.plist not found; capture binaries will not be codesigned")
endif()
