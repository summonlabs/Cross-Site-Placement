cmake_minimum_required(VERSION 3.20)

project(CrossSitePlacement
    VERSION 1.0.1
    DESCRIPTION "DCCP deterministic cross-site placement planning and explanation authority"
    HOMEPAGE_URL "https://github.com/summonlabs/Cross-Site-Placement"
    LANGUAGES CXX)

# The standard is set once, globally, so every target in every subdirectory and every
# consumer of this build tree compiles at the same language level. Setting it per target
# is easy to forget for a new target, and forgetting it silently downgrades the language
# level instead of failing.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CSP_IS_TOP_LEVEL ON)
else()
    set(CSP_IS_TOP_LEVEL OFF)
endif()

# The library is static by default. A static default keeps the ABI surface at zero and
# makes the installed package usable from any toolchain that can read the library
# format, which for a boundary like this one - a pure function over values - is worth
# more than shared-library loading. The shared build is supported and tested; on MSVC it
# relies on CMake's automatic export-symbol generation, which is stated in the README
# rather than left for a consumer to discover.
option(CSP_BUILD_SHARED "Build the cross-site placement library as a shared library" OFF)
option(CSP_BUILD_TESTS "Build the cross-site placement test suite" ${CSP_IS_TOP_LEVEL})
option(CSP_BUILD_CLI "Build the csp command-line tool" ON)
option(CSP_BUILD_EXAMPLES "Build the cross-site placement examples" ${CSP_IS_TOP_LEVEL})
option(CSP_BUILD_BENCHMARKS "Build the cross-site placement benchmarks" ${CSP_IS_TOP_LEVEL})
option(CSP_INSTALL "Generate install and package rules" ON)
option(CSP_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
set(CSP_SANITIZE "" CACHE STRING
    "Sanitizer instrumentation for first-party targets: empty, address, undefined, address+undefined, or thread")

if(CSP_BUILD_SHARED)
    set(CSP_LIBRARY_TYPE SHARED)
else()
    set(CSP_LIBRARY_TYPE STATIC)
endif()

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Shared warning and sanitizer interfaces
# ---------------------------------------------------------------------------

add_library(csp_warnings INTERFACE)
add_library(CrossSitePlacement::warnings ALIAS csp_warnings)

if(MSVC)
    target_compile_options(csp_warnings INTERFACE
        /W4
        /permissive-
        /utf-8
        /Zc:__cplusplus
        /Zc:preprocessor
        /EHsc)
    # C4251 warns that standard-library members of an exported class are not themselves
    # exported. The public surface here is deliberately made of value types with
    # standard-library members, so the warning fires on almost every public type without
    # describing a defect. The static build does not even reach it, but the shared build
    # would emit it for every type. It is suppressed once, here, rather than per class,
    # and the README records the suppression as a known, narrow exception.
    target_compile_options(csp_warnings INTERFACE /wd4251)
    if(CSP_WARNINGS_AS_ERRORS)
        target_compile_options(csp_warnings INTERFACE /WX)
    endif()
    target_compile_definitions(csp_warnings INTERFACE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(csp_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wdouble-promotion
        -Wformat=2)
    # GCC's -Wnull-dereference rests on -fdelete-null-pointer-checks and is documented to
    # be prone to false positives. At -O3 it fires inside libstdc++'s own <streambuf> when
    # a first-party translation unit uses a stream, which is a diagnostic about a system
    # header rather than about this project's code: there is nothing in first-party code to
    # fix, and the alternative - rewriting working code to appease an analysis of somebody
    # else's header - would make the code worse. The suppression is GCC-only, names one
    # diagnostic, and is recorded in the README rather than applied across the board.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(csp_warnings INTERFACE -Wno-null-dereference)
    endif()
    if(CSP_WARNINGS_AS_ERRORS)
        target_compile_options(csp_warnings INTERFACE -Werror)
    endif()
endif()

set(CSP_SANITIZER_FLAGS "")
if(CSP_SANITIZE STREQUAL "address")
    if(MSVC)
        list(APPEND CSP_SANITIZER_FLAGS /fsanitize=address)
        set(CSP_MSVC_ASAN_RUNTIME ON)
    else()
        list(APPEND CSP_SANITIZER_FLAGS -fsanitize=address -fno-omit-frame-pointer)
    endif()
elseif(CSP_SANITIZE STREQUAL "undefined")
    if(MSVC)
        message(FATAL_ERROR "CSP_SANITIZE=undefined is not supported by MSVC; the Windows build has no equivalent")
    endif()
    list(APPEND CSP_SANITIZER_FLAGS -fsanitize=undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
elseif(CSP_SANITIZE STREQUAL "address+undefined")
    if(MSVC)
        message(FATAL_ERROR "CSP_SANITIZE=address+undefined is not supported by MSVC; use address alone")
    endif()
    list(APPEND CSP_SANITIZER_FLAGS
        -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
elseif(CSP_SANITIZE STREQUAL "thread")
    if(MSVC)
        message(FATAL_ERROR "CSP_SANITIZE=thread is not supported by MSVC")
    endif()
    list(APPEND CSP_SANITIZER_FLAGS -fsanitize=thread -fno-omit-frame-pointer)
elseif(NOT CSP_SANITIZE STREQUAL "")
    message(FATAL_ERROR "Unsupported CSP_SANITIZE value: ${CSP_SANITIZE}")
endif()

add_library(csp_sanitizer INTERFACE)
add_library(CrossSitePlacement::sanitizer ALIAS csp_sanitizer)
if(CSP_SANITIZER_FLAGS)
    target_compile_options(csp_sanitizer INTERFACE ${CSP_SANITIZER_FLAGS})
    if(MSVC)
        # MSVC records the sanitizer runtime in the instrumented objects' metadata and
        # treats /fsanitize=address as a compile option only, so passing it to the linker
        # makes the linker warn about an option it does not recognise. Incremental linking
        # is incompatible with that metadata, so it is turned off here rather than left
        # for the linker to refuse with a warning.
        target_link_options(csp_sanitizer INTERFACE /INCREMENTAL:NO)
    else()
        target_link_options(csp_sanitizer INTERFACE ${CSP_SANITIZER_FLAGS})
    endif()
endif()

# ---------------------------------------------------------------------------
# First-party sources
# ---------------------------------------------------------------------------

set(CSP_PUBLIC_HEADERS
    include/cross_site_placement/cancellation.hpp
    include/cross_site_placement/core.hpp
    include/cross_site_placement/cross_site_placement.hpp
    include/cross_site_placement/engine.hpp
    include/cross_site_placement/error.hpp
    include/cross_site_placement/evidence.hpp
    include/cross_site_placement/limits.hpp
    include/cross_site_placement/measurement.hpp
    include/cross_site_placement/persistence.hpp
    include/cross_site_placement/plan.hpp
    include/cross_site_placement/policy.hpp
    include/cross_site_placement/request.hpp
    include/cross_site_placement/revalidate.hpp
    include/cross_site_placement/strong_types.hpp
    include/cross_site_placement/text.hpp
    include/cross_site_placement/version.hpp)

set(CSP_INTERNAL_HEADERS
    src/checked.hpp
    src/crc32.hpp
    src/domain_graph.hpp
    src/engine_internal.hpp
    src/fs_atomic.hpp
    src/json.hpp
    src/parallel.hpp
    src/sha256.hpp
    src/store_format.hpp)

set(CSP_SOURCES
    src/checked.cpp
    src/core.cpp
    src/crc32.cpp
    src/domain_graph.cpp
    src/engine.cpp
    src/engine_candidates.cpp
    src/engine_latency.cpp
    src/engine_search.cpp
    src/error.cpp
    src/evidence.cpp
    src/fs_atomic.cpp
    src/json.cpp
    src/limits.cpp
    src/parallel.cpp
    src/persistence.cpp
    src/plan.cpp
    src/policy.cpp
    src/request.cpp
    src/revalidate.cpp
    src/sha256.cpp
    src/store_format.cpp
    src/strong_types.cpp
    src/text_parse.cpp
    src/text_render.cpp
    src/version.cpp)

add_library(csp_objects OBJECT ${CSP_SOURCES} ${CSP_INTERNAL_HEADERS})
set_target_properties(csp_objects PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)
target_include_directories(csp_objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(csp_objects
    PRIVATE CrossSitePlacement::warnings CrossSitePlacement::sanitizer)

if(CSP_MSVC_ASAN_RUNTIME)
    target_compile_options(csp_objects PRIVATE /fsanitize=address)
endif()

# ---------------------------------------------------------------------------
# Public library target
# ---------------------------------------------------------------------------

add_library(CrossSitePlacement ${CSP_LIBRARY_TYPE} $<TARGET_OBJECTS:csp_objects>)
add_library(CrossSitePlacement::CrossSitePlacement ALIAS CrossSitePlacement)

set_target_properties(CrossSitePlacement PROPERTIES
    OUTPUT_NAME cross_site_placement
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

target_include_directories(CrossSitePlacement
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# The warning and sanitizer interfaces exist only inside this build tree. A static
# library normally carries its private link dependencies into the interface it exports,
# and exporting them would make an installed package require targets that are not
# installed at all. Wrapping them keeps them strictly inside this tree, so the exported
# target depends on nothing but Threads, which the package configuration finds itself.
target_link_libraries(CrossSitePlacement
    PRIVATE $<BUILD_INTERFACE:CrossSitePlacement::sanitizer>
            $<BUILD_INTERFACE:CrossSitePlacement::warnings>)

if(CSP_MSVC_ASAN_RUNTIME)
    target_compile_options(CrossSitePlacement PRIVATE /fsanitize=address)
endif()

if(WIN32 AND CSP_BUILD_SHARED)
    # The public surface is value types and free functions rather than annotated
    # classes, so on MSVC the export table is generated from the compiled objects
    # instead of from __declspec annotations in the headers.
    set_target_properties(CrossSitePlacement PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# The same objects again as a static library for first-party executables. It exists so
# that tests, the CLI, and the benchmarks link one artifact regardless of the shared
# option, and so that a shared build cannot make a test pass or fail for a reason that
# has nothing to do with the library.
add_library(csp_static STATIC $<TARGET_OBJECTS:csp_objects>)
set_target_properties(csp_static PROPERTIES OUTPUT_NAME cross_site_placement_static)
target_include_directories(csp_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(csp_static PUBLIC CrossSitePlacement::sanitizer CrossSitePlacement::warnings)

find_package(Threads REQUIRED)
target_link_libraries(csp_static PUBLIC Threads::Threads)
target_link_libraries(CrossSitePlacement PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# Installation and package export
# ---------------------------------------------------------------------------

if(CSP_INSTALL)
    install(TARGETS CrossSitePlacement
        EXPORT CrossSitePlacementTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(DIRECTORY include/cross_site_placement
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.hpp")

    set(CSP_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/CrossSitePlacement)

    install(EXPORT CrossSitePlacementTargets
        FILE CrossSitePlacementTargets.cmake
        NAMESPACE CrossSitePlacement::
        DESTINATION ${CSP_CMAKE_DIR})

    configure_package_config_file(
        cmake/CrossSitePlacementConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/CrossSitePlacementConfig.cmake
        INSTALL_DESTINATION ${CSP_CMAKE_DIR})

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/CrossSitePlacementConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
        ARCH_INDEPENDENT)

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/CrossSitePlacementConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/CrossSitePlacementConfigVersion.cmake
        DESTINATION ${CSP_CMAKE_DIR})

    install(FILES README.md LICENSE NOTICE CONTRIBUTING.md
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
endif()

# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

set(CPACK_PACKAGE_NAME "CrossSitePlacement")
set(CPACK_PACKAGE_VENDOR "Summon Software Labs")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "DCCP deterministic cross-site placement planning and explanation authority")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_CONTACT "Summon Software Labs")
set(CPACK_PACKAGE_CHECKSUM SHA256)
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)

# A multi-configuration generator puts the shared library in a per-configuration
# directory, and that directory is not on the loader's search path for an executable
# sitting in its own directory. First-party executables that link the shared library
# therefore get a copy placed beside them, which is what keeps the CLI and the examples
# runnable straight from the build tree.
function(csp_place_library target)
    if(CSP_BUILD_SHARED)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:CrossSitePlacement>
                $<TARGET_FILE_DIR:${target}>
            COMMENT "Placing the cross-site placement library beside ${target}")
    endif()
endfunction()

# CTest has to be enabled before any directory that registers a test, and the examples
# register tests as well as the test suite does. A directory added before
# enable_testing() has its add_test() calls dropped silently, so the ordering here is
# what keeps the examples inside ctest.
if(CSP_BUILD_TESTS OR CSP_BUILD_EXAMPLES)
    enable_testing()
endif()

if(CSP_BUILD_CLI)
    add_subdirectory(cli)
endif()

if(CSP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(CSP_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(CSP_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
