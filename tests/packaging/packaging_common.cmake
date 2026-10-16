# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# Shared helpers for the packaging::* CTest drivers (run via `cmake -P`).

function(_run)
  cmake_parse_arguments(R "" "DESC;OUTPUT" "CMD" ${ARGN})
  execute_process(COMMAND ${R_CMD}
                  RESULT_VARIABLE _rc
                  OUTPUT_VARIABLE _out
                  ERROR_VARIABLE _err)
  if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "FAILED: ${R_DESC}\nrc=${_rc}\nstdout:\n${_out}\nstderr:\n${_err}")
  endif()
  if(R_OUTPUT)
    set(${R_OUTPUT} "${_out}" PARENT_SCOPE)
  endif()
  message(STATUS "ok: ${R_DESC}")
endfunction()

function(_require_vars)
  foreach(_v ${ARGN})
    if(NOT DEFINED ${_v})
      message(FATAL_ERROR "missing -D${_v}")
    endif()
  endforeach()
endfunction()

function(_assert_exists _path _desc)
  if(NOT EXISTS "${_path}")
    message(FATAL_ERROR "FAILED: ${_desc}: expected ${_path}")
  endif()
  message(STATUS "ok: ${_desc}")
endfunction()

function(_assert_not_exists _path _desc)
  if(EXISTS "${_path}")
    message(FATAL_ERROR "FAILED: ${_desc}: did not expect ${_path}")
  endif()
  message(STATUS "ok: ${_desc}")
endfunction()

function(_assert_file_equals _path _expected _desc)
  file(READ "${_path}" _actual)
  if(NOT _actual STREQUAL _expected)
    message(FATAL_ERROR "FAILED: ${_desc}: ${_path} holds '${_actual}'")
  endif()
  message(STATUS "ok: ${_desc}")
endfunction()

function(_assert_matches _text _regex _desc)
  if(NOT _text MATCHES "${_regex}")
    message(FATAL_ERROR "FAILED: ${_desc}: no match for '${_regex}' in:\n${_text}")
  endif()
  message(STATUS "ok: ${_desc}")
endfunction()

function(_assert_cache_lacks _build_dir _regex _desc)
  file(STRINGS "${_build_dir}/CMakeCache.txt" _hits REGEX "${_regex}")
  if(_hits)
    message(FATAL_ERROR "FAILED: ${_desc}: cache has ${_hits}")
  endif()
  message(STATUS "ok: ${_desc}")
endfunction()

# Flags that turn any Catch2 request into a configure error, offline. Before
# CMake 3.30 FETCHCONTENT_FULLY_DISCONNECTED alone silently skips population;
# an absent FETCHCONTENT_SOURCE_DIR_CATCH2 makes a fetch request fatal.
macro(_set_no_catch2_flags _var _work)
  set(${_var}
      -DCMAKE_DISABLE_FIND_PACKAGE_Catch2=ON
      -DFETCHCONTENT_FULLY_DISCONNECTED=ON
      "-DFETCHCONTENT_SOURCE_DIR_CATCH2=${_work}/no-such-catch2")
endmacro()
