cmake_minimum_required(VERSION 3.20)

project(xniff VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

add_library(xniff SHARED
    Sources/libxniff/xniff.c
)
target_include_directories(xniff
    PUBLIC
        ${PROJECT_SOURCE_DIR}/Sources/shared
)
set_target_properties(xniff PROPERTIES
    OUTPUT_NAME xniff
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

add_executable(xniff-cli
    Sources/xniff-cli/main.c
)
target_link_libraries(xniff-cli PRIVATE xniff)

add_executable(xniff-test
    Sources/xniff-tests/main.c
)
target_link_libraries(xniff-test PRIVATE xniff)
