# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# iora_embed_assets() build-time code generator (run via `cmake -P`).
# Architecture: coding_trackers/architecture/iora/asset_pipeline.json (R-5/R-11/M-f).
#
# Pure-CMake emitter: file(READ ... HEX) for byte arrays, file(SHA256) for ETags.
# No Python/xxd/bin2c. Emits a self-contained header defining one
# EmbeddedAssetRegistry instance consumed by iora::web::Assets::fromEmbedded.
#
# Inputs (passed via -D on the cmake -P command line):
#   GEN_MANIFEST     - path to the manifest written by iora_embed_assets()
#   GEN_OUT          - output header path
#   GEN_REGISTRY     - C++ identifier of the emitted registry instance
#   GEN_EXTERNAL_DIR - runtime EXTERNAL_DIR (may be empty)
#   GEN_GZIP         - path to a gzip executable (empty => no precompression)
#
# Manifest line grammar (one per asset):
#   STATIC|<key>|<abspath>|<gzipFlag 0|1>
#   TEMPLATE|<name>|<abspath>
#   EXTERNAL|<relpath>

cmake_minimum_required(VERSION 3.14)

# Convert a HEX string ("48656c") to a C initializer ("0x48,0x65,0x6c,").
function(_iea_hex_to_init hex out_var)
  string(REGEX REPLACE "(..)" "0x\\1," _init "${hex}")
  set(${out_var} "${_init}" PARENT_SCOPE)
endfunction()

# Escape a string for a C++ double-quoted literal (defense-in-depth: the module
# already rejects \ and " in asset paths, but the generator may run standalone).
function(_iea_cstr in out_var)
  string(REPLACE "\\" "\\\\" _e "${in}")
  string(REPLACE "\"" "\\\"" _e "${_e}")
  set(${out_var} "${_e}" PARENT_SCOPE)
endfunction()

# Emit a `static const unsigned char <ident>[] = {...};` for a file's bytes and
# return the C++ string_view expression naming it (or an empty string_view for a
# zero-byte file). Appends the array definition to the named accumulator.
function(_iea_emit_bytes ident abspath arrays_var view_out)
  file(READ "${abspath}" _hex HEX)
  string(LENGTH "${_hex}" _hexlen)
  math(EXPR _bytelen "${_hexlen} / 2")
  if(_bytelen EQUAL 0)
    set(${view_out} "std::string_view()" PARENT_SCOPE)
    return()
  endif()
  _iea_hex_to_init("${_hex}" _init)
  set(_arr "static const unsigned char ${ident}[] = { ${_init} };\n")
  set(${arrays_var} "${${arrays_var}}${_arr}" PARENT_SCOPE)
  set(${view_out}
      "std::string_view(reinterpret_cast<const char*>(${ident}), ${_bytelen})"
      PARENT_SCOPE)
endfunction()

if(NOT DEFINED GEN_MANIFEST OR NOT EXISTS "${GEN_MANIFEST}")
  message(FATAL_ERROR "IoraEmbedAssetsGen: missing GEN_MANIFEST (${GEN_MANIFEST})")
endif()
if(NOT DEFINED GEN_OUT)
  message(FATAL_ERROR "IoraEmbedAssetsGen: missing GEN_OUT")
endif()
if(NOT DEFINED GEN_REGISTRY OR GEN_REGISTRY STREQUAL "")
  set(GEN_REGISTRY "kEmbeddedAssets")
endif()

file(STRINGS "${GEN_MANIFEST}" _lines)

set(_arrays "")          # byte-array definitions
set(_statics_sortable "") # "key###<cpp entry>"
set(_templates_sortable "")
set(_external_sortable "") # "relpath###\"relpath\""
set(_ident_counter 0)

foreach(_line IN LISTS _lines)
  if(_line STREQUAL "")
    continue()
  endif()
  string(REPLACE "|" ";" _parts "${_line}")
  list(GET _parts 0 _type)

  if(_type STREQUAL "STATIC")
    list(GET _parts 1 _key)
    list(GET _parts 2 _abspath)
    list(GET _parts 3 _gzipflag)
    math(EXPR _ident_counter "${_ident_counter} + 1")
    string(MAKE_C_IDENTIFIER "iea_${GEN_REGISTRY}_s${_ident_counter}" _ident)
    _iea_emit_bytes("${_ident}_b" "${_abspath}" _arrays _bytesview)
    file(SHA256 "${_abspath}" _sha)
    string(SUBSTRING "${_sha}" 0 32 _etag)

    set(_gzipview "std::nullopt")
    set(_gzipetag "")
    if(_gzipflag STREQUAL "1" AND NOT GEN_GZIP STREQUAL "")
      set(_tmpgz "${GEN_OUT}.${_ident}.gz")
      execute_process(COMMAND "${GEN_GZIP}" -9 -c "${_abspath}"
                      OUTPUT_FILE "${_tmpgz}" RESULT_VARIABLE _gzrc)
      if(_gzrc EQUAL 0 AND EXISTS "${_tmpgz}")
        _iea_emit_bytes("${_ident}_gz" "${_tmpgz}" _arrays _gzbytesview)
        file(SHA256 "${_tmpgz}" _gzsha)
        string(SUBSTRING "${_gzsha}" 0 32 _gzipetag)
        set(_gzipview "std::optional<std::string_view>(${_gzbytesview})")
      endif()
      # Clean up the scratch .gz on every path (success or partial failure).
      file(REMOVE "${_tmpgz}")
    endif()

    _iea_cstr("${_key}" _keyc)
    set(_entry "  { \"${_keyc}\", ${_bytesview}, \"${_etag}\", ${_gzipview}, \"${_gzipetag}\" },")
    list(APPEND _statics_sortable "${_key}###${_entry}")

  elseif(_type STREQUAL "TEMPLATE")
    list(GET _parts 1 _name)
    list(GET _parts 2 _abspath)
    math(EXPR _ident_counter "${_ident_counter} + 1")
    string(MAKE_C_IDENTIFIER "iea_${GEN_REGISTRY}_t${_ident_counter}" _ident)
    _iea_emit_bytes("${_ident}_b" "${_abspath}" _arrays _bytesview)
    _iea_cstr("${_name}" _namec)
    set(_entry "  { \"${_namec}\", ${_bytesview} },")
    list(APPEND _templates_sortable "${_name}###${_entry}")

  elseif(_type STREQUAL "EXTERNAL")
    list(GET _parts 1 _relpath)
    _iea_cstr("${_relpath}" _relpathc)
    list(APPEND _external_sortable "${_relpath}###  std::string_view(\"${_relpathc}\"),")
  endif()
endforeach()

# Sort tables by key so runtime binary_search works; then strip the sort prefix.
function(_iea_render_sorted sortable_var out_var)
  set(_items "${${sortable_var}}")
  list(SORT _items)
  set(_rendered "")
  foreach(_it IN LISTS _items)
    string(REGEX REPLACE "^[^#]*###" "" _line "${_it}")
    set(_rendered "${_rendered}${_line}\n")
  endforeach()
  set(${out_var} "${_rendered}" PARENT_SCOPE)
endfunction()

_iea_render_sorted(_statics_sortable _statics_block)
_iea_render_sorted(_templates_sortable _templates_block)
_iea_render_sorted(_external_sortable _external_block)

list(LENGTH _statics_sortable _statics_count)
list(LENGTH _templates_sortable _templates_count)
list(LENGTH _external_sortable _external_count)

# Assemble the header.
set(_h "// Generated by iora_embed_assets() — DO NOT EDIT.\n")
string(APPEND _h "// Include this header in EXACTLY ONE translation unit.\n")
string(APPEND _h "#pragma once\n")
string(APPEND _h "#include <iora/web/assets.hpp>\n")
string(APPEND _h "#include <optional>\n")
string(APPEND _h "#include <string_view>\n\n")
# Byte arrays + registry tables/instance are emitted at file scope with internal
# linkage (static); the header is single-TU-by-contract. No `using namespace`
# (avoids the in-header using-directive anti-pattern); the table initializers
# reference the file-scope array identifiers directly.
string(APPEND _h "${_arrays}\n")

if(_templates_count GREATER 0)
  string(APPEND _h "static const iora::web::EmbeddedTemplate ${GEN_REGISTRY}_templates[] = {\n${_templates_block}};\n\n")
  set(_templates_ptr "${GEN_REGISTRY}_templates")
else()
  set(_templates_ptr "nullptr")
endif()

if(_statics_count GREATER 0)
  string(APPEND _h "static const iora::web::EmbeddedAsset ${GEN_REGISTRY}_statics[] = {\n${_statics_block}};\n\n")
  set(_statics_ptr "${GEN_REGISTRY}_statics")
else()
  set(_statics_ptr "nullptr")
endif()

if(_external_count GREATER 0)
  string(APPEND _h "static const std::string_view ${GEN_REGISTRY}_external[] = {\n${_external_block}};\n\n")
  set(_external_ptr "${GEN_REGISTRY}_external")
else()
  set(_external_ptr "nullptr")
endif()

_iea_cstr("${GEN_EXTERNAL_DIR}" _extdirc)
string(APPEND _h "static const iora::web::EmbeddedAssetRegistry ${GEN_REGISTRY} = {\n")
string(APPEND _h "  ${_templates_ptr}, ${_templates_count},\n")
string(APPEND _h "  ${_statics_ptr}, ${_statics_count},\n")
string(APPEND _h "  std::string_view(\"${_extdirc}\"),\n")
string(APPEND _h "  ${_external_ptr}, ${_external_count},\n")
string(APPEND _h "};\n")

file(WRITE "${GEN_OUT}" "${_h}")
message(STATUS "iora_embed_assets: wrote ${GEN_OUT} (${_statics_count} statics, ${_templates_count} templates, ${_external_count} external)")
