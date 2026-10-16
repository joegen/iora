# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# packaging::test_subproject_consumer — iora consumed from source as a
# subproject, via (A) add_subdirectory and (B) FetchContent SOURCE_DIR.
# Asserts, offline: configure + build succeed; iora's tests are not built and
# Catch2 is never requested (even though the consumer sets BUILD_TESTS=ON);
# a target linking iora_lib and one linking only iora_core both run.
#
# Inputs (-D): IORA_SRC, CONSUMER_SRC, WORK_DIR

cmake_minimum_required(VERSION 3.14)
include("${CMAKE_CURRENT_LIST_DIR}/packaging_common.cmake")
_require_vars(IORA_SRC CONSUMER_SRC WORK_DIR)

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}")
_set_no_catch2_flags(_no_catch2 "${WORK_DIR}")

foreach(_mode add_subdirectory fetchcontent)
  set(_b "${WORK_DIR}/build_${_mode}")
  _run(DESC "${_mode}: configure consumer"
       CMD ${CMAKE_COMMAND} -S "${CONSUMER_SRC}" -B "${_b}"
           "-DIORA_SRC=${IORA_SRC}" "-DIORA_CONSUME_MODE=${_mode}" ${_no_catch2})
  # Defect (c): a configure that never requests Catch2 leaves no
  # CATCH_BUILD_STATIC_LIBRARY entry in its cache.
  _assert_cache_lacks("${_b}" "^CATCH_BUILD_STATIC_LIBRARY" "${_mode}: Catch2 not requested")
  _assert_cache_lacks("${_b}" "^BUILD_(SAMPLES|EXAMPLES):"
                      "${_mode}: iora's BUILD_SAMPLES/BUILD_EXAMPLES not declared")
  if(_mode STREQUAL "add_subdirectory")
    set(_iora_bin "${_b}/iora")
  else()
    set(_iora_bin "${_b}/_deps/iora-build")
  endif()
  foreach(_sub tests sample examples)
    _assert_not_exists("${_iora_bin}/${_sub}" "${_mode}: iora ${_sub} not configured")
  endforeach()
  _run(DESC "${_mode}: build consumer"
       CMD ${CMAKE_COMMAND} --build "${_b}" --parallel 2)
  _run(DESC "${_mode}: run target linking iora_lib" CMD "${_b}/uses_lib")
  _run(DESC "${_mode}: run target linking only iora_core" CMD "${_b}/uses_core")
endforeach()

message(STATUS "packaging::test_subproject_consumer: ALL assertions passed")
