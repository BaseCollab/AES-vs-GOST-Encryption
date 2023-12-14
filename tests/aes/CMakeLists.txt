cmake_minimum_required(VERSION 3.13)

set(SOURCES aes_test.cpp)

add_library(aes_test_impl OBJECT ${SOURCES})
target_include_directories(aes_test_impl PUBLIC ${ENC_ROOT})

add_dependencies(aes_test_impl aes_impl)
target_link_libraries(aes_test_impl PUBLIC aes_impl)
