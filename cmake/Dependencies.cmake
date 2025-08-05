# Dependencies.cmake - Smart dependency management with system library detection
# This module checks for system-installed libraries before falling back to FetchContent

include(FetchContent)

# Helper function to check for system libraries and fall back to FetchContent
function(find_or_fetch_dependency)
    set(options REQUIRED)
    set(oneValueArgs 
        NAME 
        PACKAGE_NAME 
        TARGET_NAME
        GIT_REPOSITORY 
        GIT_TAG
        INCLUDE_DIR
        SYSTEM_INCLUDE_HINTS
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
    
    # Try to find the system-installed package first
    if(FIND_OR_FETCH_COMPONENTS)
        find_package(${FIND_OR_FETCH_PACKAGE_NAME} QUIET COMPONENTS ${FIND_OR_FETCH_COMPONENTS})
    else()
        find_package(${FIND_OR_FETCH_PACKAGE_NAME} QUIET)
    endif()
    
    # Check if the package was found
    if(${FIND_OR_FETCH_PACKAGE_NAME}_FOUND OR ${FIND_OR_FETCH_NAME}_FOUND)
        message(STATUS "Using system-installed ${FIND_OR_FETCH_NAME}")
        
        # Create an alias target if it doesn't exist
        if(NOT TARGET ${FIND_OR_FETCH_TARGET_NAME} AND TARGET ${FIND_OR_FETCH_PACKAGE_NAME})
            add_library(${FIND_OR_FETCH_TARGET_NAME} ALIAS ${FIND_OR_FETCH_PACKAGE_NAME})
        endif()
        
    else()
        # Fall back to FetchContent
        message(STATUS "${FIND_OR_FETCH_NAME} not found in system, using FetchContent")
        
        if(NOT FIND_OR_FETCH_GIT_REPOSITORY OR NOT FIND_OR_FETCH_GIT_TAG)
            message(FATAL_ERROR "GIT_REPOSITORY and GIT_TAG must be specified for ${FIND_OR_FETCH_NAME}")
        endif()
        
        FetchContent_Declare(
            ${FIND_OR_FETCH_NAME}
            GIT_REPOSITORY ${FIND_OR_FETCH_GIT_REPOSITORY}
            GIT_TAG ${FIND_OR_FETCH_GIT_TAG}
        )
        
        FetchContent_MakeAvailable(${FIND_OR_FETCH_NAME})
        
        # Set include directory variable for backwards compatibility
        if(FIND_OR_FETCH_INCLUDE_DIR)
            set(${FIND_OR_FETCH_INCLUDE_DIR} "${CMAKE_BINARY_DIR}/_deps/${FIND_OR_FETCH_NAME}-src/include" PARENT_SCOPE)
        endif()
    endif()
endfunction()

# Configure all dependencies
function(configure_iora_dependencies)
    # nlohmann_json
    find_or_fetch_dependency(
        NAME nlohmann_json
        PACKAGE_NAME nlohmann_json
        TARGET_NAME nlohmann_json::nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.2
        INCLUDE_DIR NLOHMANN_JSON_INCLUDE_DIR
    )
    
    # Catch2 (for testing)
    find_or_fetch_dependency(
        NAME Catch2
        PACKAGE_NAME Catch2
        TARGET_NAME Catch2::Catch2WithMain
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
        INCLUDE_DIR CATCH2_INCLUDE_DIR
    )
    
    # cpp-httplib
    find_or_fetch_dependency(
        NAME cpp_httplib
        PACKAGE_NAME httplib
        TARGET_NAME httplib::httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.10.8
        INCLUDE_DIR CPP_HTTPLIB_INCLUDE_DIR
    )
    
    # cpr - Note: This takes longer to build due to curl dependency (~2-3 minutes)
    message(STATUS "Configuring cpr (HTTP client library)...")
    find_or_fetch_dependency(
        NAME cpr
        PACKAGE_NAME cpr
        TARGET_NAME cpr::cpr
        GIT_REPOSITORY https://github.com/libcpr/cpr.git
        GIT_TAG 1.10.0
        INCLUDE_DIR CPR_INCLUDE_DIR
    )
    
    # tomlplusplus
    find_or_fetch_dependency(
        NAME tomlplusplus
        PACKAGE_NAME tomlplusplus
        TARGET_NAME tomlplusplus::tomlplusplus
        GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
        GIT_TAG v3.3.0
        INCLUDE_DIR TOMLPLUSPLUS_INCLUDE_DIR
    )
    
    # cpp-subprocess
    find_or_fetch_dependency(
        NAME subprocess
        PACKAGE_NAME subprocess
        TARGET_NAME subprocess::subprocess
        GIT_REPOSITORY https://github.com/arun11299/cpp-subprocess.git
        GIT_TAG master
        INCLUDE_DIR SUBPROCESS_INCLUDE_DIR
    )
    
    # Set backwards compatibility include directories for FetchContent builds
    if(NOT nlohmann_json_FOUND)
        set(NLOHMANN_JSON_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include" PARENT_SCOPE)
    endif()
    
    if(NOT Catch2_FOUND)
        set(CATCH2_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/catch2-src/include" PARENT_SCOPE)
    endif()
    
    if(NOT httplib_FOUND)
        set(CPP_HTTPLIB_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/cpp_httplib-src" PARENT_SCOPE)
    endif()
    
    if(NOT cpr_FOUND)
        set(CPR_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/cpr-src/include" PARENT_SCOPE)
    endif()
    
    if(NOT tomlplusplus_FOUND)
        set(TOMLPLUSPLUS_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/tomlplusplus-src/include" PARENT_SCOPE)
    endif()
    
    if(NOT subprocess_FOUND)
        set(SUBPROCESS_INCLUDE_DIR "${CMAKE_BINARY_DIR}/_deps/subprocess-src/cpp-subprocess" PARENT_SCOPE)
    endif()
    
    # Optional tiktoken dependency
    find_path(TIKTOKEN_INCLUDE_DIR tiktoken/encodings.h)
    find_library(TIKTOKEN_LIBRARY NAMES tiktoken)
    
    if(TIKTOKEN_INCLUDE_DIR AND TIKTOKEN_LIBRARY)
        message(STATUS "Found tiktoken: ${TIKTOKEN_INCLUDE_DIR}, ${TIKTOKEN_LIBRARY}")
        set(TIKTOKEN_FOUND TRUE PARENT_SCOPE)
        set(TIKTOKEN_INCLUDE_DIR ${TIKTOKEN_INCLUDE_DIR} PARENT_SCOPE)
        set(TIKTOKEN_LIBRARY ${TIKTOKEN_LIBRARY} PARENT_SCOPE)
    else()
        message(STATUS "tiktoken not found: Tokenizer will use fallback mode.")
        set(TIKTOKEN_FOUND FALSE PARENT_SCOPE)
    endif()
endfunction()