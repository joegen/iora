# CMake configuration for the sample microservice application

add_executable(microservice_example microservice_example.cpp)
target_link_libraries(microservice_example PRIVATE iora_lib)

# Update toml++ include directory to use the explicit path
set(TOMLPLUSPLUS_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/tomlplusplus-src/include")
target_include_directories(microservice_example PRIVATE ${TOMLPLUSPLUS_INCLUDE_DIR})

# Add nlohmann_json include directory
set(NLOHMANN_JSON_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include")
target_include_directories(microservice_example PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})

# Add cpp-httplib include directory
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

# --- OpenSSL for cpp-httplib SSL support ---
find_package(OpenSSL REQUIRED)
target_link_libraries(microservice_example PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Define CPPHTTPLIB_OPENSSL_SUPPORT globally for all targets
add_definitions(-DCPPHTTPLIB_OPENSSL_SUPPORT)

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
