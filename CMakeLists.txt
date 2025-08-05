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

# Include our modular CMake files
include(cmake/Dependencies.cmake)
include(cmake/IoraTargets.cmake)

# Configure all dependencies with system library detection
configure_iora_dependencies()

# Create the main iora_lib interface library
create_iora_lib()

# Enable testing support
include(CTest)
enable_testing()

# Add subdirectories
add_subdirectory(tests)
add_subdirectory(sample)

# Add a custom target for `make check` to run all tests
add_custom_target(check 
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS all_tests
    COMMENT "Running all tests with CTest"
)

# Installation configuration
include(GNUInstallDirs)

# Install the header files
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hpp"
)

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
