# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs
#
# The benchmark links the same static artifact the tests and the CLI link, so a number it
# prints describes the library and not a differently built copy of it.
add_executable(csp_benchmark benchmark_planning.cpp)
set_target_properties(csp_benchmark PROPERTIES OUTPUT_NAME csp-benchmark)
target_link_libraries(csp_benchmark PRIVATE csp_static)
if(TARGET csp_sanitizer)
    target_link_libraries(csp_benchmark PRIVATE csp_sanitizer)
endif()
if(TARGET csp_warnings)
    target_link_libraries(csp_benchmark PRIVATE csp_warnings)
endif()
csp_place_library(csp_benchmark)
