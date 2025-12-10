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

# Runtime dylib to inject into target processes
file(GLOB XNIFF_RT_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-rt/*.c"
)
add_library(xniff-rt SHARED ${XNIFF_RT_SOURCES})
target_include_directories(xniff-rt PUBLIC ${PROJECT_SOURCE_DIR}/Sources/xniff-rt)
set_target_properties(xniff-rt PROPERTIES OUTPUT_NAME xniff-rt)

file(GLOB XNIFF_CLI_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-cli/*.S"
)

add_executable(xniff-cli ${XNIFF_CLI_SOURCES})
target_link_libraries(xniff-cli PRIVATE xniff PkgConfig::CAPSTONE)
target_include_directories(xniff-cli PRIVATE ${PROJECT_SOURCE_DIR}/Sources/libxniff/include)

file(GLOB XNIFF_TEST_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xniff-tests/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-tests/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xniff-tests/*.S"
)

add_executable(xniff-test ${XNIFF_TEST_SOURCES})
target_link_libraries(xniff-test PRIVATE)

# Optional: xpcdesert CLI (built if sources are present)
file(GLOB XPCDESERT_SOURCES CONFIGURE_DEPENDS
    "${PROJECT_SOURCE_DIR}/Sources/xpcdesert/*.c"
    "${PROJECT_SOURCE_DIR}/Sources/xpcdesert/*.s"
    "${PROJECT_SOURCE_DIR}/Sources/xpcdesert/*.S"
)

if(XPCDESERT_SOURCES)
    add_executable(xpcdesert ${XPCDESERT_SOURCES})
    target_include_directories(xpcdesert PRIVATE ${PROJECT_SOURCE_DIR}/Sources/libxniff/include)
    target_link_libraries(xpcdesert PRIVATE xniff PkgConfig::CAPSTONE)
endif()

# macOS codesigning with JIT entitlements (for testing self-modifying code)
if(APPLE)
    set(XNIFF_ENTITLEMENTS "${PROJECT_SOURCE_DIR}/macos.entitlements.plist")
    if(EXISTS "${XNIFF_ENTITLEMENTS}")
        add_custom_command(TARGET xniff POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff>"
            COMMENT "Codesigning libxniff with JIT entitlements")

        add_custom_command(TARGET xniff-rt POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-rt>"
            COMMENT "Codesigning xniff-rt with JIT entitlements")

        add_custom_command(TARGET xniff-test POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-test>"
            COMMENT "Codesigning xniff-test with JIT entitlements")

        add_custom_command(TARGET xniff-cli POST_BUILD
            COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xniff-cli>"
            COMMENT "Codesigning xniff-cli with JIT entitlements")

        if(TARGET xpcdesert)
            add_custom_command(TARGET xpcdesert POST_BUILD
                COMMAND codesign --force -s - --options runtime --entitlements "${XNIFF_ENTITLEMENTS}" "$<TARGET_FILE:xpcdesert>"
                COMMENT "Codesigning xpcdesert with JIT entitlements")
        endif()
    else()
        message(WARNING "macos.entitlements.plist not found; binaries will not be codesigned.")
    endif()
endif()
