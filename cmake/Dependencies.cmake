# Dependencies.cmake - Smart dependency management with system library detection
# This module checks for system-installed libraries before falling back to FetchContent

include(FetchContent)

# Helper function to check for system libraries and fall back to FetchContent
function(find_or_fetch_dependency)
    set(options EXACT)
    set(oneValueArgs
        NAME
        PACKAGE_NAME
        TARGET_NAME
        VERSION
        GIT_REPOSITORY
        GIT_TAG
    )
    set(multiValueArgs COMPONENTS)
    
    cmake_parse_arguments(FIND_OR_FETCH "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    # Set default values
    if(NOT FIND_OR_FETCH_PACKAGE_NAME)
        set(FIND_OR_FETCH_PACKAGE_NAME ${FIND_OR_FETCH_NAME})
    endif()
    
    if(NOT FIND_OR_FETCH_TARGET_NAME)
        set(FIND_OR_FETCH_TARGET_NAME ${FIND_OR_FETCH_NAME})
    endif()
    
    # Build the version constraint passed to find_package(). When VERSION is given,
    # find_package() rejects a system package that does not satisfy it (and with
    # EXACT, only an exact match is accepted) — forcing the FetchContent fallback,
    # rather than silently building against a mismatched system version.
    set(_fof_version_args "")
    if(FIND_OR_FETCH_VERSION)
        list(APPEND _fof_version_args ${FIND_OR_FETCH_VERSION})
        if(FIND_OR_FETCH_EXACT)
            list(APPEND _fof_version_args EXACT)
        endif()
    endif()

    # Try to find the system-installed package first (version-matched)
    if(FIND_OR_FETCH_COMPONENTS)
        find_package(${FIND_OR_FETCH_PACKAGE_NAME} ${_fof_version_args} QUIET COMPONENTS ${FIND_OR_FETCH_COMPONENTS})
    else()
        find_package(${FIND_OR_FETCH_PACKAGE_NAME} ${_fof_version_args} QUIET)
    endif()
    
    # Determine whether a USABLE system package was found (D-7): it must be FOUND
    # (version-matched) AND the requested TARGET_NAME must be available — exists
    # directly, or can be aliased from the package's own target. A version-matched
    # system package may still lack the requested target (e.g. a header-only Catch2
    # install exports Catch2::Catch2 but NOT Catch2::Catch2WithMain). Version match
    # does not imply target availability.
    set(_fof_found FALSE)
    if(${FIND_OR_FETCH_PACKAGE_NAME}_FOUND OR ${FIND_OR_FETCH_NAME}_FOUND)
        set(_fof_found TRUE)
    endif()
    set(_fof_use_system FALSE)
    if(_fof_found)
        if(TARGET ${FIND_OR_FETCH_TARGET_NAME})
            set(_fof_use_system TRUE)
        elseif(TARGET ${FIND_OR_FETCH_PACKAGE_NAME})
            add_library(${FIND_OR_FETCH_TARGET_NAME} ALIAS ${FIND_OR_FETCH_PACKAGE_NAME})
            set(_fof_use_system TRUE)
        elseif(FIND_OR_FETCH_TARGET_NAME STREQUAL "Catch2::Catch2WithMain" AND TARGET Catch2::Catch2)
            # Header-only Catch2 v2 install: it exports Catch2::Catch2 but not
            # Catch2::Catch2WithMain. Fetching is not possible (the imported
            # Catch2::Catch2 collides with the fetched ALIAS), so build the
            # compiled-main archive over the system headers instead. PUBLIC so
            # the test targets get the Catch2 include dir through this link.
            set(_fof_main_src "${CMAKE_CURRENT_BINARY_DIR}/iora_catch2_with_main.cpp")
            if(NOT EXISTS "${_fof_main_src}")
                file(WRITE "${_fof_main_src}" "#define CATCH_CONFIG_MAIN\n#include <catch2/catch.hpp>\n")
            endif()
            add_library(iora_catch2_with_main STATIC "${_fof_main_src}")
            target_link_libraries(iora_catch2_with_main PUBLIC Catch2::Catch2)
            add_library(Catch2::Catch2WithMain ALIAS iora_catch2_with_main)
            message(STATUS "Catch2: system package has no Catch2::Catch2WithMain; built it from the system headers")
            set(_fof_use_system TRUE)
        endif()
    endif()

    if(_fof_use_system)
        message(STATUS "Using system-installed ${FIND_OR_FETCH_NAME} (version ${${FIND_OR_FETCH_PACKAGE_NAME}_VERSION}) via target ${FIND_OR_FETCH_TARGET_NAME}")
        # FIND path: a package's config dir often ships CMake helper modules beside
        # its <Pkg>Config.cmake (e.g. Catch2's Catch.cmake, which provides
        # catch_discover_tests). find_package() does NOT add that dir to
        # CMAKE_MODULE_PATH, so a later include(<Helper>) fails on the find path
        # (it only works on the fetch path, where <lc>_SOURCE_DIR/contrib is added).
        # Export the config dir onto CMAKE_MODULE_PATH so include() of such helpers
        # resolves identically on both the find and fetch paths.
        if(DEFINED ${FIND_OR_FETCH_PACKAGE_NAME}_DIR AND IS_DIRECTORY "${${FIND_OR_FETCH_PACKAGE_NAME}_DIR}")
            list(APPEND CMAKE_MODULE_PATH "${${FIND_OR_FETCH_PACKAGE_NAME}_DIR}")
            set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH}" PARENT_SCOPE)
        endif()
    else()
        # A version-matched package WAS found but does not provide the requested
        # target. Do NOT FetchContent over it — the imported target would collide
        # with the fetched build's target. Fail clearly with remediation instead.
        if(_fof_found)
            message(FATAL_ERROR "${FIND_OR_FETCH_NAME}: system package found (version ${${FIND_OR_FETCH_PACKAGE_NAME}_VERSION}) but it does not provide the required target '${FIND_OR_FETCH_TARGET_NAME}'. Rebuild/reinstall it with that target enabled, or uninstall the system package so the pinned version is fetched instead.")
        endif()
        # Fall back to FetchContent (not found, or version mismatch)
        if(FIND_OR_FETCH_VERSION)
            message(STATUS "${FIND_OR_FETCH_NAME} ${FIND_OR_FETCH_VERSION} not found in system (or version mismatch), using FetchContent")
        else()
            message(STATUS "${FIND_OR_FETCH_NAME} not found in system, using FetchContent")
        endif()

        if(NOT FIND_OR_FETCH_GIT_REPOSITORY OR NOT FIND_OR_FETCH_GIT_TAG)
            message(FATAL_ERROR "GIT_REPOSITORY and GIT_TAG must be specified for ${FIND_OR_FETCH_NAME}")
        endif()
        
        FetchContent_Declare(
            ${FIND_OR_FETCH_NAME}
            GIT_REPOSITORY ${FIND_OR_FETCH_GIT_REPOSITORY}
            GIT_TAG ${FIND_OR_FETCH_GIT_TAG}
        )
        
        FetchContent_MakeAvailable(${FIND_OR_FETCH_NAME})

        # Propagate the fetched source dir (lowercased per FetchContent convention)
        # to the caller, so callers can locate package-shipped CMake helpers (e.g.
        # Catch2's contrib/Catch.cmake) on the fetch path. Set ONLY when fetched —
        # callers use 'if(DEFINED <lc>_SOURCE_DIR)' to distinguish fetch vs find.
        string(TOLOWER "${FIND_OR_FETCH_NAME}" _fof_lc_name)
        if(DEFINED ${_fof_lc_name}_SOURCE_DIR)
            set(${_fof_lc_name}_SOURCE_DIR "${${_fof_lc_name}_SOURCE_DIR}" PARENT_SCOPE)
        endif()
    endif()
endfunction()

# Configure all dependencies
function(configure_iora_dependencies)
    # Catch2 (for testing) - Using v2 for compatibility. Requested only when
    # iora's own tests are built (top-level with BUILD_TESTS), so a subproject
    # or a -DBUILD_TESTS=OFF configure never fetches it.
    #
    # The test targets link Catch2::Catch2WithMain (cmake/IoraTargets.cmake): a
    # STATIC library whose main() object the linker pulls only for the test
    # executables that do NOT define their own (the ones using CATCH_CONFIG_MAIN
    # supply their own main and the archive's main is simply not pulled — no
    # collision). Catch2 v2.13.10 only DEFINES that target under
    # CATCH_BUILD_STATIC_LIBRARY, which defaults OFF — so on the FetchContent
    # fallback path (no system Catch2 installed) the target would be missing and
    # every test would fail to configure. Force it ON before the fetch so the
    # build is self-contained and reproducible without a system Catch2 package.
    if(IORA_IS_TOP_LEVEL AND BUILD_TESTS)
        set(CATCH_BUILD_STATIC_LIBRARY ON CACHE BOOL
            "Build Catch2 compiled-main static lib (provides Catch2::Catch2WithMain)" FORCE)
        find_or_fetch_dependency(
            NAME Catch2
            PACKAGE_NAME Catch2
            TARGET_NAME Catch2::Catch2WithMain
            VERSION 2.13.10
            EXACT
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v2.13.10
        )
    endif()

    # Threads - Required globally (iora_core, all targets via configure_threading_support)
    find_package(Threads REQUIRED)

    # OpenSSL - Required for HTTPS support in homegrown HTTP client
    find_package(OpenSSL REQUIRED)
    if(OpenSSL_FOUND)
        message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
    else()
        message(FATAL_ERROR "OpenSSL is required but not found")
    endif()
endfunction()
