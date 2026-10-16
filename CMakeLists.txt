cmake_minimum_required(VERSION 3.14)
project(iora 
    VERSION 1.0.0
    DESCRIPTION "Modern C++17 microservice foundation library (headers + libiora_core)"
    LANGUAGES CXX
)

# TRUE when iora is the top-level project; FALSE under add_subdirectory /
# FetchContent, where tests, samples and examples are never built.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(IORA_IS_TOP_LEVEL TRUE)
else()
    set(IORA_IS_TOP_LEVEL FALSE)
endif()

# Set default build type (top-level only; a consumer owns its build type)
if(IORA_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Tests, samples and examples: options default ON and exist only when iora is the
# top-level project. As a subproject they are never built, and a consumer's own
# BUILD_TESTS / BUILD_SAMPLES / BUILD_EXAMPLES cache entries are not read.
if(IORA_IS_TOP_LEVEL)
    option(BUILD_TESTS "Build test executables" ON)
    option(BUILD_SAMPLES "Build sample programs" ON)
    option(BUILD_EXAMPLES "Build documentation example programs" ON)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# Compiler cache
option(IORA_USE_CCACHE "Use ccache as the compiler launcher when available" ON)
if(IORA_USE_CCACHE)
    find_program(CCACHE_PROGRAM ccache)
    if(CCACHE_PROGRAM)
        set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
        set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    endif()
endif()

# Split DWARF debug info (smaller objects, lower link-time memory; no-op without -g)
option(IORA_USE_SPLIT_DWARF "Use -gsplit-dwarf to reduce debug-info size and link memory" ON)
if(IORA_USE_SPLIT_DWARF)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-gsplit-dwarf" IORA_HAVE_SPLIT_DWARF)
    if(IORA_HAVE_SPLIT_DWARF)
        add_compile_options(-gsplit-dwarf)
    endif()
endif()

# Install directories (must be before any add_subdirectory that references them)
include(GNUInstallDirs)

# RPATH configuration so installed binaries find libiora_core.so. $ORIGIN-relative,
# so the install still works after `cmake --install --prefix <other>`.
file(RELATIVE_PATH _iora_bin_to_lib "${CMAKE_INSTALL_FULL_BINDIR}" "${CMAKE_INSTALL_FULL_LIBDIR}")
set(CMAKE_INSTALL_RPATH "$ORIGIN/${_iora_bin_to_lib}")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Installed config directory for iora.cfg. An absolute CMAKE_INSTALL_SYSCONFDIR
# (e.g. -DCMAKE_INSTALL_SYSCONFDIR=/etc for packagers) is used as is; otherwise it
# is <prefix>/<sysconfdir>. GNUInstallDirs' /usr->/etc and /opt->/etc/opt special
# cases are deliberately not applied. _iora_installed_config_file is the
# configure-time path compiled into the iora executable (src/CMakeLists.txt);
# _iora_config_dir_code is the same directory for install(CODE), with the prefix
# escaped so it is read at install time.
if(IS_ABSOLUTE "${CMAKE_INSTALL_SYSCONFDIR}")
    set(_iora_sysconfdir_is_absolute TRUE)
    set(_iora_installed_config_file "${CMAKE_INSTALL_SYSCONFDIR}/iora.conf.d/iora.cfg")
    set(_iora_config_dir_code "${CMAKE_INSTALL_SYSCONFDIR}/iora.conf.d")
else()
    set(_iora_sysconfdir_is_absolute FALSE)
    set(_iora_installed_config_file "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/iora.conf.d/iora.cfg")
    set(_iora_config_dir_code "\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_SYSCONFDIR}/iora.conf.d")
endif()

# Include our modular CMake files
include(cmake/Dependencies.cmake)
include(cmake/IoraTargets.cmake)
include(cmake/AbiInvariant.cmake)

# Enforce the ServiceRegistry cross-.so ABI precondition (R-12): no
# -fvisibility=hidden / -fno-rtti. Fails configuration if violated.
iora_assert_abi_invariant()

# Configure all dependencies with system library detection
configure_iora_dependencies()

# Build the iora_core shared library (must exist before create_iora_lib)
add_subdirectory(src/core)

# Create the main iora_lib interface library (links iora_core)
create_iora_lib()

if(IORA_IS_TOP_LEVEL AND BUILD_TESTS)
    # Enable testing support
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
    
    # Add a custom target for `make check` to run all tests
    add_custom_target(check 
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        COMMENT "Running all individual tests with CTest"
    )
endif()

if(IORA_IS_TOP_LEVEL AND BUILD_SAMPLES)
    add_subdirectory(sample)
endif()

# Documentation flagship examples (CI-built; a broken headline API breaks the
# build). See docs/manifest.json and the doc-wiki initiative.
if(IORA_IS_TOP_LEVEL AND BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Always build the main source
add_subdirectory(src)



# Installation configuration
# (GNUInstallDirs already included near the top of this file)

# Install the header files
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

# Install iora.cfg into <sysconfdir>/iora.conf.d (rule above). The prefix and
# DESTDIR are escaped so they are read at INSTALL time (`cmake --install --prefix`
# and DESTDIR are honored). file(INSTALL) prepends DESTDIR itself; only the
# no-overwrite guard adds it. An existing iora.cfg is never overwritten.
install(CODE "
    set(iora_config_dir \"${_iora_config_dir_code}\")
    set(iora_config_file \"\$ENV{DESTDIR}\${iora_config_dir}/iora.cfg\")
    if(NOT EXISTS \"\${iora_config_file}\")
        file(INSTALL DESTINATION \"\${iora_config_dir}\" TYPE FILE FILES \"${CMAKE_CURRENT_SOURCE_DIR}/src/config/iora.cfg.in\" RENAME iora.cfg)
    else()
        message(STATUS \"Skipping install of iora.cfg: already exists at \${iora_config_file}\")
    endif()
")

# Install the iora_lib target
install(TARGETS iora_lib iora_core
    EXPORT IoraTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Export the targets
install(EXPORT IoraTargets
    FILE IoraTargets.cmake
    NAMESPACE Iora::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Iora
)

# Create and install the config file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/IoraConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/IoraConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/IoraConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Iora
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/IoraConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/IoraConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Iora
)

# Install the iora_embed_assets() CMake module + its build-time generator,
# co-located with the package config so find_package(Iora) consumers get
# iora_embed_assets() in scope (H-6/R-14, asset_pipeline.json).
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/IoraEmbedAssets.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/IoraEmbedAssetsGen.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Iora
)

# Vendor the pinned htmx.min.js so iora_embed_assets() can self-host it
# (LD-10, no CDN). Consumers locate it via IORA_VENDORED_WEB_DIR.
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/share/iora/web/htmx.min.js"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/iora/web
)
