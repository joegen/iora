# CompilerFlags.cmake - Shared compiler configuration for all targets

# Function to set common compiler flags for Iora targets
function(set_iora_compiler_flags target_name)
    # Set C++17 standard
    target_compile_features(${target_name} PRIVATE cxx_std_17)
    
    # Common compiler warnings and flags
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target_name} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wno-unused-parameter
            -Wno-missing-field-initializers
        )
        
        # Debug flags
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            target_compile_options(${target_name} PRIVATE -g -O0)
        endif()
        
        # Release flags
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_compile_options(${target_name} PRIVATE -O3 -DNDEBUG)
        endif()
        
    elseif(MSVC)
        target_compile_options(${target_name} PRIVATE
            /W4
            /permissive-
        )
        
        # Debug flags
        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            target_compile_options(${target_name} PRIVATE /Od /Zi)
        endif()
        
        # Release flags
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_compile_options(${target_name} PRIVATE /O2 /DNDEBUG)
        endif()
    endif()
endfunction()

# Function to configure additional OpenSSL support for WebhookServer (cpp-httplib)
function(configure_openssl_support target_name)
    # OpenSSL is now linked by default for all targets
    # This function now only adds cpp-httplib specific definitions
    target_compile_definitions(${target_name} PRIVATE 
        CPPHTTPLIB_OPENSSL_SUPPORT
    )
    
    message(STATUS "Configured WebhookServer OpenSSL support for ${target_name}")
endfunction()

# Function to configure threading support
function(configure_threading_support target_name)
    find_package(Threads REQUIRED)
    target_link_libraries(${target_name} PRIVATE Threads::Threads)
endfunction()