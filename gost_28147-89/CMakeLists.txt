cmake_minimum_required(VERSION 3.13)

set(SOURCES gost.cpp)

add_library(gost_impl OBJECT ${SOURCES})
target_include_directories(gost_impl PUBLIC ${ENC_ROOT})
