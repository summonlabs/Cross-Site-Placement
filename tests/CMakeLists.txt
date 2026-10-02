# The suite is one executable rather than one per file. Cases register themselves, so the
# only thing this file fixes is which translation units are linked in, and a case that is
# added to an existing file needs no build-system change at all.
set(CSP_TEST_SOURCES
    test_harness.cpp
    test_main.cpp
    test_values.cpp
    test_documents.cpp
    test_placement.cpp
    test_separation.cpp
    test_latency.cpp
    test_adversarial.cpp
    test_property.cpp
    test_concurrency.cpp
    test_persistence.cpp
    test_revalidate.cpp
    test_cli.cpp
    test_multiprocess.cpp)

add_executable(csp_tests ${CSP_TEST_SOURCES})
set_target_properties(csp_tests PROPERTIES OUTPUT_NAME csp-tests)
target_include_directories(csp_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(csp_tests PRIVATE csp_static)
csp_place_library(csp_tests)

# The independent OS-process tests need a second real process. A thread is not a process,
# and a claim about multiprocess behaviour must not rest on one.
add_executable(csp_multiprocess_helper helper/csp_multiprocess_helper.cpp)
set_target_properties(csp_multiprocess_helper PROPERTIES OUTPUT_NAME csp-multiprocess-helper)
target_link_libraries(csp_multiprocess_helper PRIVATE csp_static)
csp_place_library(csp_multiprocess_helper)
add_dependencies(csp_tests csp_multiprocess_helper)

if(TARGET csp_cli)
    target_compile_definitions(csp_tests PRIVATE CSP_CLI_PATH="$<TARGET_FILE:csp_cli>")
endif()
if(TARGET csp_benchmark)
    target_compile_definitions(csp_tests PRIVATE CSP_BENCHMARK_PATH="$<TARGET_FILE:csp_benchmark>")
endif()
target_compile_definitions(csp_tests PRIVATE CSP_MULTIPROCESS_HELPER="$<TARGET_FILE:csp_multiprocess_helper>")

# No TIMEOUT property, deliberately. A hanging case is a defect to diagnose, not a case to
# kill, and a suite that kills it would report the defect as a pass.
add_test(NAME csp.suite COMMAND csp_tests)
