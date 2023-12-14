cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
project(ENC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(ENC_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(ENC_BINARY_ROOT ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic -Wall -Wextra -Werror -Wshadow")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")

# --------------------------clang-format--------------------------------------

file(GLOB_RECURSE ALL_SOURCES_FILES *.cpp *.h)

find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format-14 clang-format)

add_custom_target(clang-force-format
    COMMAND ${CLANG_FORMAT_EXECUTABLE}
    -i
    -style=file
    --verbose
    ${ALL_SOURCES_FILES}
)

# -----------------------------openssl----------------------------------------

find_package(OpenSSL REQUIRED)

message("OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message("OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# --------------------------project-libs--------------------------------------

add_subdirectory(aes)
add_subdirectory(argparser)
add_subdirectory(chacha20)

add_library(enc_static STATIC)
target_link_libraries(enc_static PUBLIC
    aes_impl
    argparser_impl
    chacha20_impl
    ${OPENSSL_LIBRARIES}
)

# --------------------------google-tests--------------------------------------

enable_testing()
find_package(GTest REQUIRED)

message("GTest libraries: ${GTEST_LIBRARIES}")

add_executable(unit_tests)

target_link_libraries(unit_tests PUBLIC
    enc_static
    GTest::gtest_main
)

add_subdirectory(tests)

# ----------------------------------------------------------------------------

add_executable(enc main.cpp)
target_include_directories(enc PUBLIC ${ENC_ROOT})
target_link_libraries(enc PUBLIC enc_static)
