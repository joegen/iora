# CMake configuration for Iora tests

# List of individual test files (without extensions)
set(INDIVIDUAL_TESTS
    iora_test_logger
    iora_test_event_queue
    iora_test_expiring_cache
    iora_test_iora_service
    iora_test_config_loader
    iora_test_state
    iora_test_threadpool
    iora_test_plugin
    iora_test_http
    iora_test_webhook_transport
    iora_test_shared_udp
    iora_test_shared_tcp
    iora_test_shared_transport_timers
    iora_test_unified_tcp_udp
    iora_test_transport_improvements
    iora_test_batch_processor
    iora_test_batch_integration
    iora_test_dns_client
    iora_test_timer
    iora_test_json_parser
    iora_test_xml_parser
)

# Function to create individual test executables
function(create_individual_test test_name)
    # Use the existing helper function for proper configuration
    create_iora_test_target(${test_name}
        SOURCES ${test_name}.cpp
    )
    
    # Add compile definition for test resource directory
    target_compile_definitions(${test_name} PRIVATE
        IORA_TEST_RESOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )
    
    # Add the test to CTest
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# Create all individual test executables
foreach(test_name ${INDIVIDUAL_TESTS})
    create_individual_test(${test_name})
endforeach()

# Create a test target that runs all individual tests
add_custom_target(test_all
    COMMENT "Running all individual tests"
)

foreach(test_name ${INDIVIDUAL_TESTS})
    add_custom_command(TARGET test_all POST_BUILD
        COMMAND ${test_name}
        COMMENT "Running ${test_name}"
        VERBATIM
    )
endforeach()

# Build test plugins for dynamic loading tests
add_subdirectory(plugins)