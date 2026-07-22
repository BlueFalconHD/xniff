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

find_program(XNIFF_SWIFT_EXECUTABLE swift REQUIRED)
if(CMAKE_CONFIGURATION_TYPES)
    message(FATAL_ERROR "xniff requires a single-config CMake generator")
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(XNIFF_SWIFT_CONFIGURATION debug)
else()
    set(XNIFF_SWIFT_CONFIGURATION release)
endif()
set(XNIFF_SWIFT_BUILD_DIR "${CMAKE_BINARY_DIR}/swiftpm")
set(XNIFF_SWIFT_COMMON_ARGUMENTS
    --package-path "${PROJECT_SOURCE_DIR}"
    --scratch-path "${XNIFF_SWIFT_BUILD_DIR}"
    --configuration "${XNIFF_SWIFT_CONFIGURATION}")
file(GLOB_RECURSE XNIFF_SWIFT_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/Viewer/*.swift")

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

add_library(xniff-record STATIC Sources/Capture/Protocol/xniff_record.c)
target_include_directories(xniff-record PUBLIC Sources/Capture/Protocol)
set_target_properties(xniff-record PROPERTIES POSITION_INDEPENDENT_CODE ON)
xniff_enable_arm64e(xniff-record)

add_library(xniff-transport STATIC Sources/Capture/Protocol/xniff_transport.c)
target_include_directories(xniff-transport PUBLIC Sources/Capture/Protocol)
set_target_properties(xniff-transport PROPERTIES POSITION_INDEPENDENT_CODE ON)
xniff_enable_arm64e(xniff-transport)

add_library(xniff-injector STATIC
    Sources/Capture/Injector/src/dylib_inject_stub.S
    Sources/Capture/Injector/src/inject.c
    Sources/Capture/Injector/src/macho_symbols.c
    Sources/Capture/Injector/src/patch.c)
target_include_directories(xniff-injector PUBLIC Sources/Capture/Injector/include)
xniff_enable_arm64e(xniff-injector)

add_library(xniff-hook-state STATIC
    Sources/Capture/Hooks/xpc_reply_tracker.c
    Sources/Capture/Hooks/xpc_session_coalescer.c)
target_include_directories(xniff-hook-state PUBLIC Sources/Capture/Hooks)
set_target_properties(xniff-hook-state PROPERTIES POSITION_INDEPENDENT_CODE ON)
xniff_enable_arm64e(xniff-hook-state)

add_library(xniff-hooks SHARED
    Sources/Capture/Hooks/frida_gum_interceptor.c
    Sources/Capture/Hooks/xniff_hooks_api.c
    Sources/Capture/Hooks/xniff_hooks_backtrace.c
    Sources/Capture/Hooks/xniff_hooks_runtime.c
    Sources/Capture/Hooks/xpc_highlevel_hooks.c
    Sources/Capture/Hooks/xpc_hooks.c)
target_include_directories(xniff-hooks PRIVATE Sources/Capture/Hooks)
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

add_library(xniff-capture-cli-support STATIC
    Sources/Capture/CLI/cli_options.c
    Sources/Capture/CLI/launch_environment.c
    Sources/Capture/CLI/shared_transport.c
    Sources/Capture/CLI/target_identity.c)
target_include_directories(xniff-capture-cli-support PUBLIC Sources/Capture/CLI)
target_link_libraries(xniff-capture-cli-support PUBLIC xniff-injector xniff-transport)
xniff_enable_arm64e(xniff-capture-cli-support)

add_executable(xniff
    Sources/Capture/CLI/capture.c
    Sources/Capture/CLI/embedded_hooks.c
    Sources/Capture/CLI/mach_record_renderer.c
    Sources/Capture/CLI/main.c
    Sources/Capture/CLI/process_control.c
    Sources/Capture/CLI/record_renderer.c
    Sources/Capture/CLI/record_render_support.c
    Sources/Capture/CLI/xpc_record_renderer.c)
target_link_libraries(xniff PRIVATE xniff-capture-cli-support xniff-record)
xniff_enable_arm64e(xniff)
add_dependencies(xniff xniff-hooks)
set_property(TARGET xniff APPEND PROPERTY LINK_DEPENDS "$<TARGET_FILE:xniff-hooks>")
target_link_options(xniff PRIVATE
    "LINKER:-sectcreate,__DATA,__xniff_hooks,$<TARGET_FILE:xniff-hooks>")

add_executable(xniff-test
    Tests/Capture/main.c
    Tests/Capture/shared_transport_test.c
    Tests/Capture/target_user_test.c
    Tests/Capture/xpc_session_coalescer_test.c)
target_link_libraries(xniff-test PRIVATE
    xniff-capture-cli-support
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

set(XNIFF_SWIFT_OUTPUTS
    "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/xniff-viewer"
    "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/xniff-print")
add_custom_command(
    OUTPUT ${XNIFF_SWIFT_OUTPUTS}
    COMMAND "${XNIFF_SWIFT_EXECUTABLE}" build ${XNIFF_SWIFT_COMMON_ARGUMENTS}
    COMMAND "${CMAKE_COMMAND}" -E copy
            "${XNIFF_SWIFT_BUILD_DIR}/${XNIFF_SWIFT_CONFIGURATION}/xniff-viewer"
            "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/xniff-viewer"
    COMMAND "${CMAKE_COMMAND}" -E copy
            "${XNIFF_SWIFT_BUILD_DIR}/${XNIFF_SWIFT_CONFIGURATION}/xniff-print"
            "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/xniff-print"
    DEPENDS "${PROJECT_SOURCE_DIR}/Package.swift" ${XNIFF_SWIFT_SOURCES}
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    COMMENT "Building xniff viewer tools with SwiftPM"
    VERBATIM
    USES_TERMINAL)
add_custom_target(xniff-viewer-tools ALL DEPENDS ${XNIFF_SWIFT_OUTPUTS})

add_test(NAME xniff-viewer-tests
    COMMAND "${XNIFF_SWIFT_EXECUTABLE}" test ${XNIFF_SWIFT_COMMON_ARGUMENTS})

set(XNIFF_ENTITLEMENTS "${PROJECT_SOURCE_DIR}/Resources/xniff.entitlements")
function(xniff_codesign target_name)
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND codesign --force -s - --options runtime
                --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:${target_name}>"
        COMMENT "Codesigning ${target_name}")
endfunction()

if(EXISTS "${XNIFF_ENTITLEMENTS}")
    xniff_codesign(xniff-hooks)
    xniff_codesign(xniff)
else()
    message(WARNING "Resources/xniff.entitlements not found; capture binaries will not be codesigned")
endif()
