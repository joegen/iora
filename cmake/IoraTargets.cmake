# IoraTargets.cmake - Helper functions for creating Iora targets

include(cmake/CompilerFlags.cmake)

# Function to create the main iora_lib interface library
function(create_iora_lib)
    add_library(iora_lib INTERFACE)
    
    target_include_directories(iora_lib INTERFACE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    )
    
    target_compile_features(iora_lib INTERFACE cxx_std_17)
    
    message(STATUS "Created iora_lib interface library")
endfunction()

# Function to configure a target with common Iora dependencies
function(configure_iora_target target_name)
    set(options ENABLE_OPENSSL ENABLE_TIKTOKEN)
    set(oneValueArgs "")
    set(multiValueArgs LINK_LIBRARIES INCLUDE_DIRECTORIES COMPILE_DEFINITIONS)
    
    cmake_parse_arguments(CONFIG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    
    # Set compiler flags
    set_iora_compiler_flags(${target_name})
    
    # Configure threading
    configure_threading_support(${target_name})
    
    # Link with iora_lib
    target_link_libraries(${target_name} PRIVATE iora_lib)
    
    # Add common dependencies
    target_link_libraries(${target_name} PRIVATE 
        nlohmann_json::nlohmann_json
        cpr::cpr
    )
    
    # Add include directories for fetched dependencies (backwards compatibility)
    if(NLOHMANN_JSON_INCLUDE_DIR)
        target_include_directories(${target_name} PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
    endif()
    
    if(CPR_INCLUDE_DIR)
        target_include_directories(${target_name} PRIVATE ${CPR_INCLUDE_DIR})
    endif()
    
    if(CPP_HTTPLIB_INCLUDE_DIR)
        target_include_directories(${target_name} PRIVATE ${CPP_HTTPLIB_INCLUDE_DIR})
    endif()
    
    if(TOMLPLUSPLUS_INCLUDE_DIR)
        target_include_directories(${target_name} PRIVATE ${TOMLPLUSPLUS_INCLUDE_DIR})
    endif()
    
    if(SUBPROCESS_INCLUDE_DIR)
        target_include_directories(${target_name} PRIVATE ${SUBPROCESS_INCLUDE_DIR})
    endif()
    
    # Configure OpenSSL if requested
    if(CONFIG_ENABLE_OPENSSL)
        configure_openssl_support(${target_name})
    endif()
    
    # Configure tiktoken if available and requested
    if(CONFIG_ENABLE_TIKTOKEN AND TIKTOKEN_FOUND)
        target_include_directories(${target_name} PRIVATE ${TIKTOKEN_INCLUDE_DIR})
        target_link_libraries(${target_name} PRIVATE ${TIKTOKEN_LIBRARY})
        target_compile_definitions(${target_name} PRIVATE iora_USE_TIKTOKEN)
        message(STATUS "Enabled tiktoken support for ${target_name}")
    endif()
    
    # Add custom link libraries
    if(CONFIG_LINK_LIBRARIES)
        target_link_libraries(${target_name} PRIVATE ${CONFIG_LINK_LIBRARIES})
    endif()
    
    # Add custom include directories
    if(CONFIG_INCLUDE_DIRECTORIES)
        target_include_directories(${target_name} PRIVATE ${CONFIG_INCLUDE_DIRECTORIES})
    endif()
    
    # Add custom compile definitions
    if(CONFIG_COMPILE_DEFINITIONS)
        target_compile_definitions(${target_name} PRIVATE ${CONFIG_COMPILE_DEFINITIONS})
    endif()
    
    message(STATUS "Configured Iora target: ${target_name}")
endfunction()

# Function to create test targets
function(create_iora_test_target target_name)
    cmake_parse_arguments(TEST "" "" "SOURCES;LINK_LIBRARIES" ${ARGN})
    
    add_executable(${target_name} ${TEST_SOURCES})
    
    # Configure with common Iora settings and OpenSSL
    configure_iora_target(${target_name} 
        ENABLE_OPENSSL
        LINK_LIBRARIES Catch2::Catch2WithMain ${TEST_LINK_LIBRARIES}
    )
    
    # Add Catch2 include directory for fetched dependencies
    if(CATCH2_INCLUDE_DIR)
        target_include_directories(${target_name} PRIVATE ${CATCH2_INCLUDE_DIR})
    endif()
    
    message(STATUS "Created Iora test target: ${target_name}")
endfunction()

# Function to create plugin targets
function(create_iora_plugin_target target_name)
    cmake_parse_arguments(PLUGIN "" "" "SOURCES;LINK_LIBRARIES" ${ARGN})
    
    add_library(${target_name} SHARED ${PLUGIN_SOURCES})
    
    # Configure with common Iora settings and OpenSSL
    configure_iora_target(${target_name} 
        ENABLE_OPENSSL
        LINK_LIBRARIES ${PLUGIN_LINK_LIBRARIES}
    )
    
    # Set plugin-specific properties
    set_target_properties(${target_name} PROPERTIES
        OUTPUT_NAME "${target_name}"
        PREFIX ""
    )
    
    message(STATUS "Created Iora plugin target: ${target_name}")
endfunction()