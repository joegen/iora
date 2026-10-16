# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# find_package(Iora) consumer that links ONLY Iora::iora_core. Driven by
# run_install_layout_test.cmake.

cmake_minimum_required(VERSION 3.14)
project(iora_installed_core_consumer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Iora REQUIRED)

# The headers call dlopen/dlclose inline, so the exported iora_core must carry
# the dl library for consumers.
if(CMAKE_DL_LIBS)
  get_target_property(_iora_core_links Iora::iora_core INTERFACE_LINK_LIBRARIES)
  if(NOT "${CMAKE_DL_LIBS}" IN_LIST _iora_core_links)
    message(FATAL_ERROR "Iora::iora_core INTERFACE_LINK_LIBRARIES (${_iora_core_links}) lacks ${CMAKE_DL_LIBS}")
  endif()
endif()

add_executable(uses_core ../subproject_consumer/uses_iora.cpp)
target_link_libraries(uses_core PRIVATE Iora::iora_core)
