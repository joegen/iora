# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# CTest driver (run via `cmake -P`) for the out-of-tree iora_embed_assets()
# consumer test (H-6/R-14). Hermetic: installs the current iora build to a
# test-controlled prefix (NOT a shared /workspace/.install), then drives a real
# find_package(Iora) consumer sub-project through four assertions:
#   (1) iora_embed_assets() in scope after find_package(Iora) (configure fails if not)
#   (2) generated header compiles + getStatic/getTemplate/ETag/MIME correct
#   (3) incremental rebuild on a fixture CONTENT change (add_custom_command DEPENDS)
#   (4) vendored htmx.min.js present by default; NO_VENDOR_HTMX omits it;
#       a consumer-provided htmx.min.js overrides (STATUS message).
#
# Inputs (-D): IORA_BUILD_DIR, CONSUMER_SRC, WORK_DIR

cmake_minimum_required(VERSION 3.14)

foreach(_v IORA_BUILD_DIR CONSUMER_SRC WORK_DIR)
  if(NOT DEFINED ${_v})
    message(FATAL_ERROR "run_embed_assets_test: missing -D${_v}")
  endif()
endforeach()

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

set(_prefix "${WORK_DIR}/prefix")
set(_src "${WORK_DIR}/consumer_src")
file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}")

# Fresh, hermetic install of the current build (M-p).
_run(DESC "install iora to test-controlled prefix"
     CMD ${CMAKE_COMMAND} --install "${IORA_BUILD_DIR}" --prefix "${_prefix}")

# Writable copy of the consumer (so the incremental-edit step does not mutate
# the checked-in fixture).
file(COPY "${CONSUMER_SRC}/" DESTINATION "${_src}")

# M-4 / matrixNote: generate a ~256KB binary fixture so the file(READ HEX)
# large-blob codegen path is actually exercised (perf watch-item). Built here
# (not committed) to keep the repo lean. 3.14-safe (no string(REPEAT)).
set(_chunk "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
foreach(_i RANGE 1 4) # 64 -> 1024 bytes
  string(APPEND _chunk "${_chunk}")
endforeach()
set(_big "")
foreach(_i RANGE 1 256) # 1024 * 256 = 256 KiB
  string(APPEND _big "${_chunk}")
endforeach()
file(WRITE "${_src}/static/big.bin" "${_big}")

# ---- (1)+(2) default build: in-scope, compiles, runs --------------------------
set(_b1 "${WORK_DIR}/build_default")
_run(DESC "configure consumer (default, vendored htmx) — proves iora_embed_assets in scope"
     CMD ${CMAKE_COMMAND} -S "${_src}" -B "${_b1}" "-DCMAKE_PREFIX_PATH=${_prefix}")
_run(DESC "build consumer (default)"
     CMD ${CMAKE_COMMAND} --build "${_b1}")
_run(DESC "run consumer (default) — getStatic/getTemplate/ETag/MIME + htmx present"
     CMD "${_b1}/consumer" OUTPUT _bytes1)

# ---- (3) incremental rebuild on content change --------------------------------
file(WRITE "${_src}/static/app.js" "export const v=99;/*driver-edited*/")
_run(DESC "rebuild consumer after editing app.js content (DEPENDS path)"
     CMD ${CMAKE_COMMAND} --build "${_b1}")
_run(DESC "run consumer after edit" CMD "${_b1}/consumer" OUTPUT _bytes2)
if(_bytes1 STREQUAL _bytes2)
  message(FATAL_ERROR "incremental rebuild did NOT pick up the content change: '${_bytes1}'")
endif()
message(STATUS "ok: incremental rebuild reflected new content")

# ---- (4) NO_VENDOR_HTMX omits htmx --------------------------------------------
set(_b2 "${WORK_DIR}/build_novendor")
_run(DESC "configure consumer (NO_VENDOR_HTMX)"
     CMD ${CMAKE_COMMAND} -S "${_src}" -B "${_b2}"
         "-DCMAKE_PREFIX_PATH=${_prefix}" -DCONSUMER_NO_VENDOR=ON)
_run(DESC "build consumer (NO_VENDOR_HTMX)" CMD ${CMAKE_COMMAND} --build "${_b2}")
_run(DESC "run consumer (NO_VENDOR_HTMX) — htmx absent" CMD "${_b2}/consumer")

# ---- (4) consumer-provided htmx overrides vendored ----------------------------
file(WRITE "${_src}/static/htmx.min.js" "/* consumer-owned htmx */")
set(_b3 "${WORK_DIR}/build_override")
_run(DESC "configure consumer (consumer-provided htmx overrides)"
     CMD ${CMAKE_COMMAND} -S "${_src}" -B "${_b3}" "-DCMAKE_PREFIX_PATH=${_prefix}"
     OUTPUT _ovr_cfg)
if(NOT _ovr_cfg MATCHES "consumer-provided htmx.min.js overrides vendored copy")
  message(FATAL_ERROR "expected consumer-override STATUS message; not found in configure output")
endif()
_run(DESC "build consumer (override)" CMD ${CMAKE_COMMAND} --build "${_b3}")
_run(DESC "run consumer (override)" CMD "${_b3}/consumer")
message(STATUS "ok: consumer-provided htmx override honored (STATUS emitted)")

# ---- (5) negative: an unsafe asset-path character fails configure (M-2) --------
# A backslash in an asset filename (legal on POSIX) must be rejected at
# classification with a FATAL_ERROR, not silently emitted into a C++ literal.
file(WRITE "${_src}/static/bad\\name.css" "x")
set(_bneg "${WORK_DIR}/build_badname")
execute_process(COMMAND ${CMAKE_COMMAND} -S "${_src}" -B "${_bneg}"
                        "-DCMAKE_PREFIX_PATH=${_prefix}"
                RESULT_VARIABLE _negrc OUTPUT_VARIABLE _negout ERROR_VARIABLE _negerr)
file(REMOVE "${_src}/static/bad\\name.css")
if(_negrc EQUAL 0)
  message(FATAL_ERROR "expected configure to FAIL for an unsafe asset path (backslash), but it succeeded")
endif()
message(STATUS "ok: unsafe asset-path character rejected at configure (M-2)")

message(STATUS "web::test_embed_assets: ALL out-of-tree assertions passed")
