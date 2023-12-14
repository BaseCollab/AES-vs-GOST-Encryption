cmake_minimum_required(VERSION 3.13)

set(SOURCES chacha20.cpp)

add_library(chacha20_impl OBJECT ${SOURCES})
target_include_directories(chacha20_impl PUBLIC ${ENC_ROOT})
