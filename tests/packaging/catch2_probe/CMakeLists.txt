# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# Runs iora's configure_iora_dependencies() against a header-only Catch2
# package and links a probe with no main() of its own to Catch2::Catch2WithMain.
# Driven by run_catch2_header_only_test.cmake.

cmake_minimum_required(VERSION 3.14)
project(iora_catch2_probe CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include("${IORA_SRC}/cmake/Dependencies.cmake")
set(IORA_IS_TOP_LEVEL ON)
set(BUILD_TESTS ON)
configure_iora_dependencies()

add_executable(probe probe.cpp)
target_link_libraries(probe PRIVATE Catch2::Catch2WithMain)
