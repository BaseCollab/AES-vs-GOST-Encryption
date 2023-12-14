cmake_minimum_required(VERSION 3.13)

set(SOURCES chacha20_test.cpp)

add_library(chacha20_test_impl OBJECT ${SOURCES})
target_include_directories(chacha20_test_impl PUBLIC ${ENC_ROOT})

add_dependencies(chacha20_test_impl chacha20_impl)
target_link_libraries(chacha20_test_impl PUBLIC chacha20_impl)
