# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# iora_embed_assets() — walk a templates/ + static/ tree at build time and
# generate a C++ header containing per-file byte arrays, build-time SHA-256
# ETags (+ optional precompressed gzip variant with its own gzipEtag), and a
# generated iora::web::EmbeddedAssetRegistry instance consumed by
# iora::web::Assets::fromEmbedded.
#
# Architecture: coding_trackers/architecture/iora/asset_pipeline.json.
#
# Signature:
#   iora_embed_assets(
#     TARGET <name> TEMPLATES_DIR <path> STATIC_DIR <path> HEADER_OUT <path>
#     [REGISTRY_NAME <id>] [EXTERNAL_PATTERNS <glob...>] [EXTERNAL_DIR <path>]
#     [MAX_EMBEDDED_SIZE <bytes>] [PRECOMPRESS gzip] [NO_VENDOR_HTMX])
#
# In-tree consumers include() this module from the source tree directly;
# out-of-tree consumers get it transitively via find_package(Iora) (IoraConfig
# include()s it). The build-time generator IoraEmbedAssetsGen.cmake is co-located
# with this module and is invoked via `cmake -P`.

# Resolve the directory holding the build-time generator script (co-located).
set(_IORA_EMBED_ASSETS_GEN "${CMAKE_CURRENT_LIST_DIR}/IoraEmbedAssetsGen.cmake")

# Resolve the vendored web asset dir (LD-10 htmx.min.js). In-tree the module is
# at <src>/cmake/ and the asset at <src>/share/iora/web/; installed the module
# is at <prefix>/<libdir>/cmake/Iora/ and the asset at <prefix>/<datadir>/iora/web/.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../share/iora/web/htmx.min.js")
  get_filename_component(IORA_VENDORED_WEB_DIR
                         "${CMAKE_CURRENT_LIST_DIR}/../share/iora/web" ABSOLUTE)
elseif(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../../../share/iora/web/htmx.min.js")
  get_filename_component(IORA_VENDORED_WEB_DIR
                         "${CMAKE_CURRENT_LIST_DIR}/../../../share/iora/web" ABSOLUTE)
else()
  set(IORA_VENDORED_WEB_DIR "")
endif()

function(iora_embed_assets)
  set(_opts NO_VENDOR_HTMX)
  set(_one TARGET TEMPLATES_DIR STATIC_DIR HEADER_OUT REGISTRY_NAME EXTERNAL_DIR
           MAX_EMBEDDED_SIZE PRECOMPRESS)
  set(_multi EXTERNAL_PATTERNS)
  cmake_parse_arguments(IEA "${_opts}" "${_one}" "${_multi}" ${ARGN})

  # ---- required-argument validation (fail-fast at configure time) ----------
  if(NOT IEA_TARGET)
    message(FATAL_ERROR "iora_embed_assets: TARGET is required")
  endif()
  if(NOT IEA_HEADER_OUT)
    message(FATAL_ERROR "iora_embed_assets: HEADER_OUT is required")
  endif()
  if(NOT IEA_TEMPLATES_DIR OR NOT IS_DIRECTORY "${IEA_TEMPLATES_DIR}")
    message(FATAL_ERROR "iora_embed_assets: Templates dir not found: ${IEA_TEMPLATES_DIR}")
  endif()
  if(NOT IEA_STATIC_DIR OR NOT IS_DIRECTORY "${IEA_STATIC_DIR}")
    message(FATAL_ERROR "iora_embed_assets: Static dir not found: ${IEA_STATIC_DIR}")
  endif()
  if(NOT IEA_REGISTRY_NAME)
    set(IEA_REGISTRY_NAME "kEmbeddedAssets")
  endif()

  # ---- gzip availability (PRECOMPRESS gzip) ---------------------------------
  set(_gzip_exe "")
  if(IEA_PRECOMPRESS STREQUAL "gzip")
    find_program(IORA_GZIP_EXECUTABLE gzip)
    if(IORA_GZIP_EXECUTABLE)
      set(_gzip_exe "${IORA_GZIP_EXECUTABLE}")
    else()
      message(STATUS "iora_embed_assets: PRECOMPRESS gzip requested but gzip not found; skipping precompression")
    endif()
  endif()

  set(_text_exts "html;htm;css;js;mjs;json;map;svg;txt;xml")
  set(_known_exts "${_text_exts};png;jpg;jpeg;gif;webp;avif;ico;woff2;woff;ttf;otf")

  # ---- walk static/ (CONFIGURE_DEPENDS so add/remove re-runs configure) -----
  file(GLOB_RECURSE _static_rel CONFIGURE_DEPENDS RELATIVE "${IEA_STATIC_DIR}"
       "${IEA_STATIC_DIR}/*")
  file(GLOB_RECURSE _tpl_rel CONFIGURE_DEPENDS RELATIVE "${IEA_TEMPLATES_DIR}"
       "${IEA_TEMPLATES_DIR}/*")

  set(_manifest_lines "")
  set(_dep_files "")
  set(_total_bytes 0)
  set(_size_breakdown "")
  set(_consumer_has_htmx FALSE)

  foreach(_rel IN LISTS _static_rel)
    set(_abs "${IEA_STATIC_DIR}/${_rel}")
    if(IS_DIRECTORY "${_abs}")
      continue()
    endif()
    # M-2: reject path characters that would corrupt the manifest grammar
    # (|, ;, newline) or the emitted C++ string literal (", \) or break the
    # ASCII-sorted binary_search at runtime (non-ASCII). Fail fast and clearly.
    if(_rel MATCHES "[\"\\\\;|\n]" OR _rel MATCHES "[^\t -~]")
      message(FATAL_ERROR "iora_embed_assets: unsupported character in asset path '${_rel}' "
                          "(paths must be tab or printable ASCII without \" \\ ; | or newline)")
    endif()
    if(_rel STREQUAL "htmx.min.js")
      set(_consumer_has_htmx TRUE)
    endif()

    # external-pattern classification (RD-11)
    set(_is_external FALSE)
    foreach(_pat IN LISTS IEA_EXTERNAL_PATTERNS)
      string(REPLACE "." "\\." _re "${_pat}")
      string(REPLACE "*" ".*" _re "${_re}")
      if(_rel MATCHES "^${_re}$")
        set(_is_external TRUE)
      endif()
    endforeach()

    if(_is_external)
      list(APPEND _manifest_lines "EXTERNAL|${_rel}")
      continue()
    endif()

    # unknown-extension build-time notice
    get_filename_component(_ext "${_rel}" LAST_EXT)
    string(TOLOWER "${_ext}" _ext)
    string(REGEX REPLACE "^\\." "" _ext "${_ext}")
    if(NOT _ext IN_LIST _known_exts)
      message(STATUS "iora_embed_assets: ${_rel} has unknown extension '.${_ext}' -> application/octet-stream")
    endif()

    # gzip eligibility: PRECOMPRESS gzip AND text-like (skip already-compressed)
    set(_gzipflag 0)
    if(NOT _gzip_exe STREQUAL "" AND _ext IN_LIST _text_exts)
      set(_gzipflag 1)
    endif()

    file(SIZE "${_abs}" _sz)
    math(EXPR _total_bytes "${_total_bytes} + ${_sz}")
    list(APPEND _size_breakdown "    ${_rel}: ${_sz} bytes")
    list(APPEND _manifest_lines "STATIC|${_rel}|${_abs}|${_gzipflag}")
    list(APPEND _dep_files "${_abs}")
  endforeach()

  foreach(_rel IN LISTS _tpl_rel)
    set(_abs "${IEA_TEMPLATES_DIR}/${_rel}")
    if(IS_DIRECTORY "${_abs}")
      continue()
    endif()
    if(_rel MATCHES "[\"\\\\;|\n]" OR _rel MATCHES "[^\t -~]")
      message(FATAL_ERROR "iora_embed_assets: unsupported character in template path '${_rel}' "
                          "(paths must be tab or printable ASCII without \" \\ ; | or newline)")
    endif()
    list(APPEND _manifest_lines "TEMPLATE|${_rel}|${_abs}")
    list(APPEND _dep_files "${_abs}")
  endforeach()

  # ---- vendored htmx.min.js injection (LD-10) -------------------------------
  if(NOT IEA_NO_VENDOR_HTMX)
    if(_consumer_has_htmx)
      message(STATUS "iora_embed_assets: consumer-provided htmx.min.js overrides vendored copy")
    elseif(NOT IORA_VENDORED_WEB_DIR STREQUAL "" AND
           EXISTS "${IORA_VENDORED_WEB_DIR}/htmx.min.js")
      set(_htmx_abs "${IORA_VENDORED_WEB_DIR}/htmx.min.js")
      set(_gzipflag 0)
      if(NOT _gzip_exe STREQUAL "")
        set(_gzipflag 1) # .js is text-like
      endif()
      file(SIZE "${_htmx_abs}" _sz)
      math(EXPR _total_bytes "${_total_bytes} + ${_sz}")
      list(APPEND _manifest_lines "STATIC|htmx.min.js|${_htmx_abs}|${_gzipflag}")
      list(APPEND _dep_files "${_htmx_abs}")
    else()
      message(WARNING "iora_embed_assets: vendored htmx.min.js not found (IORA_VENDORED_WEB_DIR='${IORA_VENDORED_WEB_DIR}'); pass NO_VENDOR_HTMX to suppress")
    endif()
  endif()

  # ---- MAX_EMBEDDED_SIZE soft cap (warn only; does not fail the build) ------
  if(IEA_MAX_EMBEDDED_SIZE AND _total_bytes GREATER IEA_MAX_EMBEDDED_SIZE)
    string(REPLACE ";" "\n" _breakdown_text "${_size_breakdown}")
    message(WARNING "iora_embed_assets: embedded size ${_total_bytes} bytes exceeds MAX_EMBEDDED_SIZE ${IEA_MAX_EMBEDDED_SIZE}; consider EXTERNAL_PATTERNS for large/volatile binaries.\nPer-file breakdown:\n${_breakdown_text}")
  endif()

  # ---- write the manifest + wire the build-time generator -------------------
  get_filename_component(_out_dir "${IEA_HEADER_OUT}" DIRECTORY)
  file(MAKE_DIRECTORY "${_out_dir}")
  set(_manifest "${_out_dir}/${IEA_REGISTRY_NAME}.manifest")
  string(REPLACE ";" "\n" _manifest_text "${_manifest_lines}")
  file(WRITE "${_manifest}" "${_manifest_text}\n")

  set(_ext_dir "")
  if(IEA_EXTERNAL_DIR)
    set(_ext_dir "${IEA_EXTERNAL_DIR}")
  endif()

  add_custom_command(
    OUTPUT "${IEA_HEADER_OUT}"
    COMMAND "${CMAKE_COMMAND}"
            "-DGEN_MANIFEST=${_manifest}"
            "-DGEN_OUT=${IEA_HEADER_OUT}"
            "-DGEN_REGISTRY=${IEA_REGISTRY_NAME}"
            "-DGEN_EXTERNAL_DIR=${_ext_dir}"
            "-DGEN_GZIP=${_gzip_exe}"
            -P "${_IORA_EMBED_ASSETS_GEN}"
    DEPENDS ${_dep_files} "${_manifest}" "${_IORA_EMBED_ASSETS_GEN}"
    COMMENT "iora_embed_assets: generating ${IEA_HEADER_OUT}"
    VERBATIM)

  add_custom_target(${IEA_TARGET}_${IEA_REGISTRY_NAME}_gen
                    DEPENDS "${IEA_HEADER_OUT}")
  add_dependencies(${IEA_TARGET} ${IEA_TARGET}_${IEA_REGISTRY_NAME}_gen)
  target_include_directories(${IEA_TARGET} PRIVATE "${_out_dir}")
endfunction()
