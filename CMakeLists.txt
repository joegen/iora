cmake_minimum_required(VERSION 3.14)
project(iora 
    VERSION 1.0.0
    DESCRIPTION "Modern C++17 single-header microservice foundation library"
    LANGUAGES CXX
)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# Include our modular CMake files
include(cmake/Dependencies.cmake)
include(cmake/IoraTargets.cmake)

# Configure all dependencies with system library detection
configure_iora_dependencies()

# Create the main iora_lib interface library
create_iora_lib()

# Optional: Build tests (disabled by default for external project integration)
option(BUILD_TESTS "Build test executables" ON)
if(BUILD_TESTS)
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

# Optional: Build samples (disabled by default for external project integration)
option(BUILD_SAMPLES "Build sample programs" ON)
if(BUILD_SAMPLES)
    add_subdirectory(sample)
endif()

# Always build the main source
add_subdirectory(src)



# Installation configuration
include(GNUInstallDirs)

# Install the header files
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

# Install configuration file to /etc (absolute path to avoid /usr/local/etc)
install(CODE "
    set(config_file \"${CMAKE_INSTALL_PREFIX}/etc/iora.conf.d/iora.cfg\")
    if(NOT EXISTS \"\${config_file}\")
        file(INSTALL DESTINATION \"${CMAKE_INSTALL_PREFIX}/etc/iora.conf.d\" TYPE FILE FILES \"${CMAKE_CURRENT_SOURCE_DIR}/src/config/iora.cfg.in\" RENAME iora.cfg)
    else()
        message(STATUS \"Skipping install of iora.cfg: already exists at \${config_file}\")
    endif()
")

# Install the iora_lib target
install(TARGETS iora_lib
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
