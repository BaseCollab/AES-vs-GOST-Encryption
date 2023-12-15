cmake_minimum_required(VERSION 3.13)

set(SOURCES benchmarking.cpp)

add_library(bench_impl OBJECT ${SOURCES})
target_include_directories(bench_impl PUBLIC ${ENC_ROOT})
