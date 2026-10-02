# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs
#
# The CLI is a first-party consumer of the library and of nothing else. It links the same
# static artifact the tests and the examples link, so a shared build cannot make the tool
# disagree with the library about a plan.
add_executable(csp_cli main.cpp)
set_target_properties(csp_cli PROPERTIES OUTPUT_NAME csp-cli)
target_link_libraries(csp_cli PRIVATE csp_static)

# csp_static already carries these interfaces; they are named here as well so that a
# future change to the library's own link interface cannot quietly drop them from the
# tool. Both are guarded, because a consumer build without them is still valid.
if(TARGET csp_sanitizer)
    target_link_libraries(csp_cli PRIVATE csp_sanitizer)
endif()
if(TARGET csp_warnings)
    target_link_libraries(csp_cli PRIVATE csp_warnings)
endif()

csp_place_library(csp_cli)
