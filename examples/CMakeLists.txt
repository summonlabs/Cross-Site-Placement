# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs
#
# One executable per example, each registered with ctest.
#
# No test carries a TIMEOUT property, deliberately: an example that hangs is a defect to
# diagnose, and a test that killed it would report the defect as a pass.
set(CSP_EXAMPLES
    basic_placement
    rejection_explanations
    separation_aliases
    persistence_reopen)

foreach(example IN LISTS CSP_EXAMPLES)
    add_executable(${example} ${example}.cpp)
    target_link_libraries(${example} PRIVATE csp_static)
    if(TARGET csp_sanitizer)
        target_link_libraries(${example} PRIVATE csp_sanitizer)
    endif()
    if(TARGET csp_warnings)
        target_link_libraries(${example} PRIVATE csp_warnings)
    endif()
    csp_place_library(${example})
    add_test(NAME csp.example.${example} COMMAND ${example})
endforeach()

# examples/consumer is a standalone project and is deliberately not added here. Its whole
# purpose is to prove that an installed package is usable without this build tree, so the
# test below configures, builds, and runs it against an install prefix. Without
# CSP_CONSUMER_PREFIX there is no prefix to test against, and the test is skipped rather
# than replaced by something that only looks like a consumption check.
if(CSP_CONSUMER_PREFIX)
    add_test(NAME csp.example.consumer-installed
        COMMAND ${CMAKE_CTEST_COMMAND} --build-and-test
                "${CMAKE_CURRENT_SOURCE_DIR}/consumer"
                "${CMAKE_CURRENT_BINARY_DIR}/consumer-installed"
                --build-generator "${CMAKE_GENERATOR}"
                --build-options
                    "-DCMAKE_BUILD_TYPE=$<CONFIG>"
                    "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                    "-DCMAKE_PREFIX_PATH=${CSP_CONSUMER_PREFIX}"
                --test-command
                    "${CMAKE_CURRENT_BINARY_DIR}/consumer-installed/csp-consumer${CMAKE_EXECUTABLE_SUFFIX}")
else()
    message(STATUS "CSP_CONSUMER_PREFIX is not set: the installed-package consumer test is skipped")
endif()
