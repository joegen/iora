cmake_minimum_required(VERSION 3.14)
project(iora LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable FetchContent
include(FetchContent)

# Dependencies

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
)
FetchContent_Declare(
    cpp_httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.10.8
)
FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 1.10.0
)
FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.3.0
)
FetchContent_Declare(
    subprocess
    GIT_REPOSITORY https://github.com/arun11299/cpp-subprocess.git
    GIT_TAG master
)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.4.0
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(nlohmann_json cpp_httplib cpr tomlplusplus subprocess Catch2)

# Add include directories for subprocess
include_directories(${subprocess_SOURCE_DIR}/cpp-subprocess)
include_directories(${catch2_SOURCE_DIR}/include)
include_directories(${catch2_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/include)

# Define iora_lib target
add_library(iora_lib INTERFACE)
target_include_directories(iora_lib INTERFACE ${CMAKE_SOURCE_DIR}/include)

# Add subdirectories
add_subdirectory(tests)

# Add the sample microservice application
set(SOURCES sample/microservice_example.cpp)
add_executable(microservice_example ${SOURCES})
target_link_libraries(microservice_example PRIVATE iora_lib)

# Update toml++ include directory to use the explicit path
set(TOMLPLUSPLUS_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/tomlplusplus-src/include")
target_include_directories(microservice_example PRIVATE ${TOMLPLUSPLUS_INCLUDE_DIR})
# Link tomlplusplus to microservice_example
# target_link_libraries(microservice_example PRIVATE tomlplusplus)

# Add nlohmann_json include directory
set(NLOHMANN_JSON_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include")
target_include_directories(microservice_example PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})

# Add cpp-httplib include directory
# Check for system tiktoken installation
find_path(TIKTOKEN_INCLUDE_DIR tiktoken/encodings.h)
find_library(TIKTOKEN_LIBRARY NAMES tiktoken)

if(TIKTOKEN_INCLUDE_DIR AND TIKTOKEN_LIBRARY)
  message(STATUS "Found tiktoken: ${TIKTOKEN_INCLUDE_DIR}, ${TIKTOKEN_LIBRARY}")
  target_include_directories(microservice_example PRIVATE ${TIKTOKEN_INCLUDE_DIR})
  target_link_libraries(microservice_example PRIVATE ${TIKTOKEN_LIBRARY})
  target_compile_definitions(microservice_example PUBLIC iora_USE_TIKTOKEN)
else()
  message(STATUS "tiktoken not found: Tokenizer will use fallback mode.")
endif()
set(CPP_HTTPLIB_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/cpp_httplib-src")
target_include_directories(microservice_example PRIVATE ${CPP_HTTPLIB_INCLUDE_DIR})

# Correct cpr include directory to point to the include folder
set(CPR_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/cpr-src/include")
target_include_directories(microservice_example PRIVATE ${CPR_INCLUDE_DIR})

# Link cpr to microservice_example to ensure proper configuration
FetchContent_GetProperties(cpr)
if(NOT cpr_POPULATED)
  FetchContent_Populate(cpr)
  add_subdirectory(${cpr_SOURCE_DIR} ${cpr_BINARY_DIR})
endif()
target_link_libraries(microservice_example PRIVATE cpr::cpr)

# Add a custom target for `make check` to run the all_tests executable
add_custom_target(check COMMAND all_tests DEPENDS all_tests)
