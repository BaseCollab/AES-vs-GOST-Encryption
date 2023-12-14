cmake_minimum_required(VERSION 3.13)

set(SOURCES gost_test.cpp)

add_library(gost_tests_impl OBJECT ${SOURCES})
target_include_directories(gost_tests_impl PUBLIC ${ENC_ROOT})

add_dependencies(gost_tests_impl gost_impl)
target_link_libraries(gost_tests_impl PUBLIC gost_impl)
