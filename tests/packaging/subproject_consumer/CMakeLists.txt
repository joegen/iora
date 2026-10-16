# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# Consumer that pulls the iora SOURCE tree in as a subproject (add_subdirectory
# or FetchContent). Driven by run_subproject_consumer_test.cmake.

cmake_minimum_required(VERSION 3.14)
project(iora_subproject_consumer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The consumer's own generic option; it must not switch on iora's tests.
option(BUILD_TESTS "Consumer tests" ON)

if(IORA_CONSUME_MODE STREQUAL "add_subdirectory")
  add_subdirectory("${IORA_SRC}" iora)
elseif(IORA_CONSUME_MODE STREQUAL "fetchcontent")
  include(FetchContent)
  FetchContent_Declare(iora SOURCE_DIR "${IORA_SRC}")
  FetchContent_MakeAvailable(iora)
else()
  message(FATAL_ERROR "IORA_CONSUME_MODE must be add_subdirectory or fetchcontent")
endif()

# The README subproject recipe: iora's own find_package results are not visible
# here, so the consumer finds OpenSSL and Threads itself.
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(uses_lib uses_iora.cpp)
target_link_libraries(uses_lib PRIVATE iora_lib OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

add_executable(uses_core uses_iora.cpp)
target_link_libraries(uses_core PRIVATE iora_core)
