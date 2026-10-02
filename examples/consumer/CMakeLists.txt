# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs
#
# A standalone downstream project. It is not part of the top-level build: it exists to
# be configured by hand against an installed package, so that what it proves is that the
# installed package is self-sufficient.
cmake_minimum_required(VERSION 3.20)

project(CSPConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CrossSitePlacement REQUIRED)

add_executable(csp-consumer main.cpp)
target_link_libraries(csp-consumer PRIVATE CrossSitePlacement::CrossSitePlacement)
