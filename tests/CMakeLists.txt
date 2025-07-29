# Include unified header directory
include_directories(${CMAKE_SOURCE_DIR}/include)

# Add toml++ include directory for all test targets
set(TOMLPLUSPLUS_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/tomlplusplus-src/include")
include_directories(${TOMLPLUSPLUS_INCLUDE_DIR})

# Add nlohmann_json include directory for all test targets
set(NLOHMANN_JSON_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include")
include_directories(${NLOHMANN_JSON_INCLUDE_DIR})

# Add cpp-httplib include directory for all test targets
set(CPP_HTTPLIB_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/cpp_httplib-src")
include_directories(${CPP_HTTPLIB_INCLUDE_DIR})

# Add cpr include directory for all test targets
set(CPR_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/cpr-src/include")
include_directories(${CPR_INCLUDE_DIR})

# Ensure cpr is properly linked and included globally for all test targets
FetchContent_GetProperties(cpr)
if(NOT cpr_POPULATED)
  FetchContent_Populate(cpr)
  add_subdirectory(${cpr_SOURCE_DIR} ${cpr_BINARY_DIR})
endif()
include_directories(${CPR_INCLUDE_DIR})

# Replace all individual test executables with a single amalgamated test file
add_executable(all_tests all_tests.cpp)
target_link_libraries(all_tests PRIVATE nlohmann_json Catch2WithMain iora_lib cpr::cpr)

# Build test plugins for dynamic loading tests
add_subdirectory(plugins)

# Standalone streamed POST parse logic test

# Add a custom target for `make check` to run the all_tests executable
# add_custom_target(check COMMAND all_tests DEPENDS all_tests)
