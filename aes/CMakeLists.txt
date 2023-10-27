cmake_minimum_required(VERSION 3.13)

set(SOURCES aes.cpp)

add_library(aes_impl OBJECT ${SOURCES})
target_include_directories(aes_impl PUBLIC ${ENC_ROOT})