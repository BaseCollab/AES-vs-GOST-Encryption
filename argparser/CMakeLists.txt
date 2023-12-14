cmake_minimum_required(VERSION 3.13)

set(SOURCES parser.cpp)

add_library(argparser_impl OBJECT ${SOURCES})
target_include_directories(argparser_impl PUBLIC ${ENC_ROOT})
