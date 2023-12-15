cmake_minimum_required(VERSION 3.13)

set(SOURCES main.cpp)

add_subdirectory(aes)
add_subdirectory(gost)
add_subdirectory(chacha20)

add_library(unit_test_main OBJECT main.cpp)

add_dependencies(unit_tests
    unit_test_main
    aes_test_impl
    gost_tests_impl
    chacha20_test_impl
)

target_link_libraries(unit_tests PUBLIC
    unit_test_main
    aes_test_impl
    gost_tests_impl
    chacha20_test_impl
)

add_custom_target(run_unit_tests
    COMMENT "Running unit tests"
    COMMAND ${ENC_BINARY_ROOT}/unit_tests --gtest_color=yes
)
add_dependencies(run_unit_tests unit_tests)

