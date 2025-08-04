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
# Add the sample microservice application as a subdirectory
add_subdirectory(sample)

# Add a custom target for `make check` to run the all_tests executable
add_custom_target(check COMMAND all_tests DEPENDS all_tests)
