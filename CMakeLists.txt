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

# Require Capstone via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED IMPORTED_TARGET capstone)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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

target_link_libraries(xniff PRIVATE PkgConfig::CAPSTONE)

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
    set_target_properties(xniff-hooks PROPERTIES OUTPUT_NAME xniff-hooks)
endif()

file(GLOB XNIFF_CLI_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.S"
)

add_executable(xniff-cli ${XNIFF_CLI_SOURCES} ${PROJECT_SOURCE_DIR}/Sources/shared/xniff_ipc.c)
target_link_libraries(xniff-cli PRIVATE xniff xpcdesert PkgConfig::CAPSTONE)
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
target_link_libraries(xpcdesert-cli PRIVATE xpcdesert xniff PkgConfig::CAPSTONE)

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
