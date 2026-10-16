# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# packaging::test_catch2_header_only_fallback — a version-matched Catch2 that
# exports only Catch2::Catch2 (header-only v2 install) must not fail configure;
# iora builds Catch2::Catch2WithMain over its headers instead, offline.
# (A) iora top-level configure succeeds. (B) a probe without its own main()
# links Catch2::Catch2WithMain, gets the include dir through it, and runs.
#
# Inputs (-D): IORA_SRC, IORA_CATCH2_HEADER, PROBE_SRC, WORK_DIR

cmake_minimum_required(VERSION 3.14)
include("${CMAKE_CURRENT_LIST_DIR}/packaging_common.cmake")
_require_vars(IORA_SRC IORA_CATCH2_HEADER PROBE_SRC WORK_DIR)

set(_w "${WORK_DIR}")
file(REMOVE_RECURSE "${_w}")
file(MAKE_DIRECTORY "${_w}/inc/catch2" "${_w}/pkg")

# Marker wrapper in a non-implicit include dir: the probe sees the marker only
# if the include dir reached it through Catch2::Catch2WithMain.
file(WRITE "${_w}/inc/catch2/catch.hpp"
     "#define IORA_PROBE_CATCH2_VIA_TARGET 1\n#include \"${IORA_CATCH2_HEADER}\"\n")

file(WRITE "${_w}/pkg/Catch2Config.cmake"
"if(NOT TARGET Catch2::Catch2)
  add_library(Catch2::Catch2 INTERFACE IMPORTED)
  set_target_properties(Catch2::Catch2 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES \"${_w}/inc\")
endif()
")
file(WRITE "${_w}/pkg/Catch2ConfigVersion.cmake"
"set(PACKAGE_VERSION 2.13.10)
set(PACKAGE_VERSION_COMPATIBLE TRUE)
if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
  set(PACKAGE_VERSION_EXACT TRUE)
endif()
")

set(_pkg_flags "-DCatch2_DIR=${_w}/pkg" -DFETCHCONTENT_FULLY_DISCONNECTED=ON)

# (A) iora top-level configure against the header-only package, with one test
# group on so generate needs Catch2::Catch2WithMain.
_run(DESC "(A) configure iora top-level with a header-only Catch2"
     CMD ${CMAKE_COMMAND} -S "${IORA_SRC}" -B "${_w}/build_iora" ${_pkg_flags}
         -DIORA_BUILD_CORE_TESTS=ON
     OUTPUT _a_out)
_assert_matches("${_a_out}" "system package has no Catch2::Catch2WithMain; built it from the system headers"
                "(A) Catch2::Catch2WithMain built from the system headers")

# (B) the synthesized target supplies main() and the include dir.
set(_b "${_w}/build_probe")
_run(DESC "(B) configure probe"
     CMD ${CMAKE_COMMAND} -S "${PROBE_SRC}" -B "${_b}" "-DIORA_SRC=${IORA_SRC}" ${_pkg_flags})
_run(DESC "(B) build probe" CMD ${CMAKE_COMMAND} --build "${_b}")
_run(DESC "(B) run probe" CMD "${_b}/probe" OUTPUT _probe_out)
_assert_matches("${_probe_out}" "All tests passed" "(B) synthesized Catch2::Catch2WithMain supplied main()")

message(STATUS "packaging::test_catch2_header_only_fallback: ALL assertions passed")
