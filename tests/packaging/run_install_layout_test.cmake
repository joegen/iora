# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# packaging::test_install_layout — the install honors the install-time prefix
# and DESTDIR for iora.cfg, never overwrites an existing iora.cfg, gives the
# iora executable an $ORIGIN-relative RPATH, and exports IORA_CORE_SHARED + dl
# on Iora::iora_core. Step (6) configures iora afresh with an absolute
# CMAKE_INSTALL_SYSCONFDIR, offline, with no Catch2 request. Every installed
# iora.cfg has its directory paths filled in from the install-time prefix (never
# DESTDIR).
#
# Inputs (-D): IORA_SRC, IORA_BUILD_DIR, IORA_SYSCONFDIR, IORA_BINDIR,
#              IORA_LIBDIR, IORA_LOCALSTATEDIR, CONSUMER_SRC, WORK_DIR

cmake_minimum_required(VERSION 3.15)
include("${CMAKE_CURRENT_LIST_DIR}/packaging_common.cmake")
_require_vars(IORA_SRC IORA_BUILD_DIR IORA_SYSCONFDIR IORA_BINDIR IORA_LIBDIR IORA_LOCALSTATEDIR
              CONSUMER_SRC WORK_DIR)

if(IS_ABSOLUTE "${IORA_SYSCONFDIR}")
  message(FATAL_ERROR "IORA_SYSCONFDIR '${IORA_SYSCONFDIR}' is absolute: this test would write outside ${WORK_DIR}")
endif()

set(_w "${WORK_DIR}")
file(REMOVE_RECURSE "${_w}")
file(MAKE_DIRECTORY "${_w}")
set(_cfg_rel "${IORA_SYSCONFDIR}/iora.conf.d/iora.cfg")

# The installed iora.cfg holds the exact substituted line for each directory
# path (comment lines included: the TLS lines are "#? "-marked), no leftover
# @TOKEN@, and no trace of DESTDIR. string(FIND), not a regex: the paths
# contain '.'.
function(_assert_cfg_paths _file _cfg _log _mods _destdir _desc)
  file(READ "${_file}" _text)
  foreach(_line
      "directory = \"${_mods}\""
      "file = \"${_log}/iora\""
      "file = \"${_cfg}/iora_state.json\""
      "#? certFile = \"${_cfg}/tls/server.crt\""
      "#? keyFile = \"${_cfg}/tls/server.key\""
      "#? caFile = \"${_cfg}/tls/ca.crt\"")
    string(FIND "${_text}" "${_line}" _pos)
    if(_pos EQUAL -1)
      message(FATAL_ERROR "FAILED: ${_desc}: ${_file} lacks the line: ${_line}")
    endif()
  endforeach()
  if(_text MATCHES "@[A-Za-z_]+@")
    message(FATAL_ERROR "FAILED: ${_desc}: ${_file} has an unsubstituted @TOKEN@")
  endif()
  if(_destdir)
    string(FIND "${_text}" "${_destdir}" _pos)
    if(NOT _pos EQUAL -1)
      message(FATAL_ERROR "FAILED: ${_desc}: ${_file} contains DESTDIR ${_destdir}")
    endif()
  endif()
  message(STATUS "ok: ${_desc}")
endfunction()

function(_install)
  cmake_parse_arguments(I "" "DESC;PREFIX;DESTDIR;BUILD_DIR" "" ${ARGN})
  if(NOT I_BUILD_DIR)
    set(I_BUILD_DIR "${IORA_BUILD_DIR}")
  endif()
  if(I_DESTDIR)
    set(_env ${CMAKE_COMMAND} -E env "DESTDIR=${I_DESTDIR}")
  else()
    set(_env ${CMAKE_COMMAND} -E env --unset=DESTDIR)
  endif()
  _run(DESC "${I_DESC}"
       CMD ${_env} ${CMAKE_COMMAND} --install "${I_BUILD_DIR}" --prefix "${I_PREFIX}")
endfunction()

# (1) --prefix is honored at install time.
_install(DESC "(1) install --prefix p" PREFIX "${_w}/p")
_assert_exists("${_w}/p/${_cfg_rel}" "(1) iora.cfg under the install-time prefix")
_assert_cfg_paths("${_w}/p/${_cfg_rel}" "${_w}/p/${IORA_SYSCONFDIR}/iora.conf.d"
                  "${_w}/p/${IORA_LOCALSTATEDIR}/log/iora" "${_w}/p/${IORA_LIBDIR}/iora/modules"
                  "" "(1) iora.cfg paths follow the install-time prefix")

# (2) DESTDIR is applied exactly once.
_install(DESC "(2) install DESTDIR=d --prefix p2" PREFIX "${_w}/p2" DESTDIR "${_w}/d")
_assert_exists("${_w}/d${_w}/p2/${_cfg_rel}" "(2) iora.cfg under DESTDIR+prefix")
_assert_not_exists("${_w}/d${_w}/d" "(2) DESTDIR not applied twice")
_assert_cfg_paths("${_w}/d${_w}/p2/${_cfg_rel}" "${_w}/p2/${IORA_SYSCONFDIR}/iora.conf.d"
                  "${_w}/p2/${IORA_LOCALSTATEDIR}/log/iora" "${_w}/p2/${IORA_LIBDIR}/iora/modules"
                  "${_w}/d" "(2) iora.cfg paths follow the prefix, not DESTDIR")

# (2b) the no-overwrite guard checks the staged (DESTDIR) path.
file(WRITE "${_w}/d${_w}/p2/${_cfg_rel}" "# edited-staged\n")
_install(DESC "(2b) reinstall DESTDIR=d --prefix p2" PREFIX "${_w}/p2" DESTDIR "${_w}/d")
_assert_file_equals("${_w}/d${_w}/p2/${_cfg_rel}" "# edited-staged\n" "(2b) staged iora.cfg preserved")

# (2c) an unstaged file at <prefix> does not suppress the staged install.
file(WRITE "${_w}/p2/${_cfg_rel}" "# unstaged\n")
_install(DESC "(2c) install DESTDIR=d4 --prefix p2" PREFIX "${_w}/p2" DESTDIR "${_w}/d4")
_assert_exists("${_w}/d4${_w}/p2/${_cfg_rel}" "(2c) staged iora.cfg written despite an unstaged one")

# (3) an existing installed iora.cfg is not overwritten.
file(WRITE "${_w}/p/${_cfg_rel}" "# edited\n")
_install(DESC "(3) reinstall --prefix p" PREFIX "${_w}/p")
_assert_file_equals("${_w}/p/${_cfg_rel}" "# edited\n" "(3) installed iora.cfg preserved")

# (4) the installed executable finds libiora_core through $ORIGIN.
set(_bin "${_w}/p/${IORA_BINDIR}/iora")
find_program(_readelf readelf)
if(NOT _readelf)
  message(FATAL_ERROR "readelf not found")
endif()
_run(DESC "(4) readelf -d iora" CMD "${_readelf}" -d "${_bin}" OUTPUT _dyn)
_assert_matches("${_dyn}" "R(UN)?PATH\\)[^\n]*\\[\\$ORIGIN" "(4) RUNPATH begins with $ORIGIN")
_run(DESC "(4) installed iora --help runs without LD_LIBRARY_PATH"
     CMD ${CMAKE_COMMAND} -E env --unset=LD_LIBRARY_PATH "${_bin}" --help)

# (5) find_package consumer linking only Iora::iora_core.
set(_c "${_w}/consumer_build")
_run(DESC "(5) configure find_package consumer (Iora::iora_core only)"
     CMD ${CMAKE_COMMAND} -S "${CONSUMER_SRC}" -B "${_c}" "-DCMAKE_PREFIX_PATH=${_w}/p")
_run(DESC "(5) build consumer" CMD ${CMAKE_COMMAND} --build "${_c}")
_run(DESC "(5) run consumer" CMD "${_c}/uses_core")

# (6) absolute CMAKE_INSTALL_SYSCONFDIR, offline configure, no Catch2 request.
_set_no_catch2_flags(_no_catch2 "${_w}")
set(_b6 "${_w}/build_abs")
set(_abs "${_w}/abs/etc")
_run(DESC "(6) configure iora with absolute SYSCONFDIR, tests/samples/examples OFF, offline"
     CMD ${CMAKE_COMMAND} -S "${IORA_SRC}" -B "${_b6}"
         "-DCMAKE_INSTALL_SYSCONFDIR=${_abs}" -DBUILD_TESTS=OFF -DBUILD_SAMPLES=OFF
         -DBUILD_EXAMPLES=OFF ${_no_catch2})
# Defect (c): a configure that never requests Catch2 leaves no
# CATCH_BUILD_STATIC_LIBRARY entry in its cache.
_assert_cache_lacks("${_b6}" "^CATCH_BUILD_STATIC_LIBRARY" "(6) Catch2 not requested")
_run(DESC "(6) build" CMD ${CMAKE_COMMAND} --build "${_b6}" --parallel 2)
_install(DESC "(6) install DESTDIR=d3" BUILD_DIR "${_b6}" PREFIX "${_w}/p6" DESTDIR "${_w}/d3")
_assert_exists("${_w}/d3${_abs}/iora.conf.d/iora.cfg" "(6) iora.cfg under DESTDIR + absolute SYSCONFDIR")
_assert_cfg_paths("${_w}/d3${_abs}/iora.conf.d/iora.cfg" "${_abs}/iora.conf.d"
                  "${_w}/p6/${IORA_LOCALSTATEDIR}/log/iora" "${_w}/p6/${IORA_LIBDIR}/iora/modules"
                  "${_w}/d3" "(6) iora.cfg paths: absolute SYSCONFDIR as is, others under the prefix")
file(STRINGS "${_b6}/src/iora" _paths REGEX "iora\\.conf\\.d/iora\\.cfg$")
list(FIND _paths "${_abs}/iora.conf.d/iora.cfg" _i)
if(_i EQUAL -1)
  message(FATAL_ERROR "FAILED: (6) iora binary does not contain ${_abs}/iora.conf.d/iora.cfg")
endif()
message(STATUS "ok: (6) iora default config path = installed path")

message(STATUS "packaging::test_install_layout: ALL assertions passed")
