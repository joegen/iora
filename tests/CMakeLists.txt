# CMake configuration for Iora tests
#
# By default, no tests are built to speed up compilation.
# Enable specific test groups or all tests using these options:
#
# Examples:
#   cmake -DIORA_BUILD_PARSERS_TESTS=ON        # Only parsers tests
#   cmake -DIORA_BUILD_NETWORK_TESTS=ON        # Only network tests
#   cmake -DIORA_BUILD_ALL_TESTS=ON            # All test groups
#
# Available test groups:
#   - NETWORK: Transport, DNS comprehensive, HTTP, WebSocket (13 tests)
#   - CORE: Logging, threading, timers (6 tests)
#   - PARSERS: JSON and XML parsing (2 tests)
#   - SERVICE: Plugin system and main framework (4 tests)
#   - STORAGE: Persistent storage (1 test)
#   - UTIL: Caching and utilities (1 test)
#   - DEBUG: Debug and helper tests (2 tests)
#
# Namespace-specific targets are created when enabled:
#   make test_network    # Run all network tests
#   make test_core       # Run all core tests
#   make test_parsers    # Run all parsers tests
#   etc.

# Options to enable/disable test groups (all default to OFF)
option(IORA_BUILD_NETWORK_TESTS "Build network namespace tests" OFF)
option(IORA_BUILD_CORE_TESTS "Build core namespace tests" OFF)
option(IORA_BUILD_PARSERS_TESTS "Build parsers namespace tests" OFF)
option(IORA_BUILD_UTIL_TESTS "Build util namespace tests" OFF)
option(IORA_BUILD_STORAGE_TESTS "Build storage namespace tests" OFF)
option(IORA_BUILD_SERVICE_TESTS "Build service/plugin system tests" OFF)
option(IORA_BUILD_DEBUG_TESTS "Build debug/helper tests" OFF)
option(IORA_BUILD_ALL_TESTS "Build all test groups (overrides individual options)" OFF)

# If BUILD_ALL_TESTS is ON, enable all test groups
if(IORA_BUILD_ALL_TESTS)
    set(IORA_BUILD_NETWORK_TESTS ON)
    set(IORA_BUILD_CORE_TESTS ON)
    set(IORA_BUILD_PARSERS_TESTS ON)
    set(IORA_BUILD_UTIL_TESTS ON)
    set(IORA_BUILD_STORAGE_TESTS ON)
    set(IORA_BUILD_SERVICE_TESTS ON)
    set(IORA_BUILD_DEBUG_TESTS ON)
endif()

# Network namespace tests
set(NETWORK_TESTS
    network/iora_test_batch_integration
    network/iora_test_batch_processor
    network/iora_test_dns_basic
    network/iora_test_dns_timer_cancellation
    network/iora_test_dns_async
    network/iora_test_dns_comprehensive
    network/iora_test_http
    network/iora_test_http_client_pool
    network/iora_test_shared_tcp
    network/iora_test_shared_transport_timers
    network/iora_test_shared_udp
    network/iora_test_transport_improvements
    network/iora_test_unified_tcp_udp
    network/iora_test_webhook_transport
)

# Additional network tests that might exist
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/network/iora_test_sync_async_transport.cpp")
    list(APPEND NETWORK_TESTS network/iora_test_sync_async_transport)
endif()

# Core namespace tests
set(CORE_TESTS
    core/iora_test_blocking_queue
    core/iora_test_config_loader
    core/iora_test_event_queue
    core/iora_test_external_logger
    core/iora_test_logger
    core/iora_test_threadpool
    core/iora_test_threadpool_cleanup
    core/iora_test_threadpool_lifecycle
    core/iora_test_timer
    core/iora_test_timer_lifecycle
)

# Parsers namespace tests
set(PARSERS_TESTS
    parsers/iora_test_json_parser
    parsers/iora_test_xml_parser
)

# Util namespace tests
set(UTIL_TESTS
    util/iora_test_expiring_cache
)

# Storage namespace tests
set(STORAGE_TESTS
    storage/iora_test_state
)

# Service/Plugin system tests
set(SERVICE_TESTS
    service/iora_test_iora_service
    service/iora_test_plugin
    service/iora_test_plugin_dependencies
)

# Debug/helper tests (keep in root)
set(DEBUG_TESTS
    debug_chained_test
    simple_chained_test
)

# Combine enabled tests based on options
set(ALL_TESTS)
if(IORA_BUILD_NETWORK_TESTS)
    list(APPEND ALL_TESTS ${NETWORK_TESTS})
endif()
if(IORA_BUILD_CORE_TESTS)
    list(APPEND ALL_TESTS ${CORE_TESTS})
endif()
if(IORA_BUILD_PARSERS_TESTS)
    list(APPEND ALL_TESTS ${PARSERS_TESTS})
endif()
if(IORA_BUILD_UTIL_TESTS)
    list(APPEND ALL_TESTS ${UTIL_TESTS})
endif()
if(IORA_BUILD_STORAGE_TESTS)
    list(APPEND ALL_TESTS ${STORAGE_TESTS})
endif()
if(IORA_BUILD_SERVICE_TESTS)
    list(APPEND ALL_TESTS ${SERVICE_TESTS})
endif()
if(IORA_BUILD_DEBUG_TESTS)
    list(APPEND ALL_TESTS ${DEBUG_TESTS})
endif()

# Function to create individual test executables
function(create_individual_test test_path)
    # Extract test name from path
    get_filename_component(test_name ${test_path} NAME)
    
    # Use the existing helper function for proper configuration
    create_iora_test_target(${test_name}
        SOURCES ${test_path}.cpp
    )
    
    # Add compile definition for test resource directory
    target_compile_definitions(${test_name} PRIVATE
        IORA_TEST_RESOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    
    # Add tests root directory to include path for helper headers
    target_include_directories(${test_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    
    # Add iora-sip tests directory for MockDnsServer.hpp
    target_include_directories(${test_name} PRIVATE ${CMAKE_SOURCE_DIR}/../iora-modules/iora-sip/tests)
    
    # Add the test to CTest with namespace categorization
    get_filename_component(test_dir ${test_path} DIRECTORY)
    if(test_dir)
        add_test(NAME ${test_dir}::${test_name} COMMAND ${test_name})
    else()
        add_test(NAME ${test_name} COMMAND ${test_name})
    endif()
endfunction()

# Create all individual test executables
foreach(test_path ${ALL_TESTS})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
        create_individual_test(${test_path})
    endif()
endforeach()

# Create a test target that runs all enabled individual tests
if(ALL_TESTS)
    add_custom_target(test_all
        COMMENT "Running all enabled tests"
    )

    # Add commands to run each enabled test
    foreach(test_path ${ALL_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_all POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

# Create targets for running tests by namespace (only if enabled)
if(IORA_BUILD_NETWORK_TESTS)
    add_custom_target(test_network COMMENT "Running network tests")
    foreach(test_path ${NETWORK_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_network POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_CORE_TESTS)
    add_custom_target(test_core COMMENT "Running core tests")
    foreach(test_path ${CORE_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_core POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_PARSERS_TESTS)
    add_custom_target(test_parsers COMMENT "Running parsers tests")
    foreach(test_path ${PARSERS_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_parsers POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_UTIL_TESTS)
    add_custom_target(test_util COMMENT "Running util tests")
    foreach(test_path ${UTIL_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_util POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_STORAGE_TESTS)
    add_custom_target(test_storage COMMENT "Running storage tests")
    foreach(test_path ${STORAGE_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_storage POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_SERVICE_TESTS)
    add_custom_target(test_service COMMENT "Running service tests")
    foreach(test_path ${SERVICE_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_service POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_DEBUG_TESTS)
    add_custom_target(test_debug COMMENT "Running debug tests")
    foreach(test_path ${DEBUG_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_debug POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

# Build test plugins for dynamic loading tests (only if service tests enabled)
if(IORA_BUILD_SERVICE_TESTS)
    add_subdirectory(plugins)
endif()