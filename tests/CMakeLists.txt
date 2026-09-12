# CMake configuration for Iora tests
#
# By default, no tests are built to speed up compilation.
# Enable specific test groups or all tests using these options:
#
# Examples:
#   cmake -DIORA_BUILD_PARSERS_TESTS=ON        # Only parsers tests
#   cmake -DIORA_BUILD_NETWORK_TESTS=ON        # Only network tests
#   cmake -DIORA_BUILD_RPC_TESTS=ON            # Only rpc (JSON-RPC) tests
#   cmake -DIORA_BUILD_ALL_TESTS=ON            # All test groups
#
# Available test groups:
#   - NETWORK: Transport, DNS comprehensive, HTTP, WebSocket (13 tests)
#   - CORE: Logging, threading, timers (6 tests)
#   - PARSERS: JSON and XML parsing (2 tests)
#   - SERVICE: Plugin system and main framework (4 tests)
#   - STORAGE: Persistent storage (2 tests)
#   - UTIL: Caching and utilities (1 test)
#   - DEBUG: Debug and helper tests (2 tests)
#   - WEB: Service registry, HTML/Mustache, HTTP auth, SSE, channels, HTMX (16 tests)
#   - RPC: JSON-RPC server dispatcher, HTTP endpoint mapping, client, e2e
#
# Namespace-specific targets are created when enabled:
#   make test_network    # Run all network tests
#   make test_core       # Run all core tests
#   make test_parsers    # Run all parsers tests
#   make test_web        # Run all web tests
#   make test_rpc        # Run all rpc tests
#   etc.

# Options to enable/disable test groups (all default to OFF)
option(IORA_BUILD_NETWORK_TESTS "Build network namespace tests" OFF)
option(IORA_BUILD_CORE_TESTS "Build core namespace tests" OFF)
option(IORA_BUILD_PARSERS_TESTS "Build parsers namespace tests" OFF)
option(IORA_BUILD_UTIL_TESTS "Build util namespace tests" OFF)
option(IORA_BUILD_STORAGE_TESTS "Build storage namespace tests" OFF)
option(IORA_BUILD_SERVICE_TESTS "Build service/plugin system tests" OFF)
option(IORA_BUILD_DEBUG_TESTS "Build debug/helper tests" OFF)
option(IORA_BUILD_WEB_TESTS "Build web namespace tests" OFF)
option(IORA_BUILD_RPC_TESTS "Build rpc namespace tests" OFF)
option(IORA_BUILD_ALL_TESTS "Build all test groups (overrides individual options)" OFF)

# Opt-in sanitizer build path for the concurrency tests (default OFF so normal
# builds are unaffected). TtlMap's teardown/UAF and 100x100k soak tests REQUIRE
# a sanitizer build to prove race-freedom (a non-TSan soak on x86 TSO cannot).
# TSan and ASan are mutually exclusive; TSan takes precedence if both are set.
option(IORA_ENABLE_TSAN "Build sanitized test targets with ThreadSanitizer" OFF)
option(IORA_ENABLE_ASAN "Build sanitized test targets with AddressSanitizer" OFF)

# If BUILD_ALL_TESTS is ON, enable all test groups
if(IORA_BUILD_ALL_TESTS)
    set(IORA_BUILD_NETWORK_TESTS ON)
    set(IORA_BUILD_CORE_TESTS ON)
    set(IORA_BUILD_PARSERS_TESTS ON)
    set(IORA_BUILD_UTIL_TESTS ON)
    set(IORA_BUILD_STORAGE_TESTS ON)
    set(IORA_BUILD_SERVICE_TESTS ON)
    set(IORA_BUILD_DEBUG_TESTS ON)
    set(IORA_BUILD_WEB_TESTS ON)
    set(IORA_BUILD_RPC_TESTS ON)
endif()

# Network namespace tests
set(NETWORK_TESTS
    network/iora_test_batch_processor
    network/iora_test_sockaddr_utils
    network/iora_test_name_resolver
    network/iora_test_dns_basic
    network/iora_test_dns_timer_cancellation
    network/iora_test_dns_async
    network/iora_test_dns_comprehensive
    network/iora_test_http
    network/iora_test_http_request_framing
    network/iora_test_http_client_pool
    network/iora_test_http_client_lease
    network/iora_test_http_client_response_framing
    network/iora_test_http_client_host_header
    network/iora_test_http_client_header_validation
    network/iora_test_http_client_controlled_fields
    network/iora_test_http_client_multipart
    network/iora_test_http_client_parseurl
    network/iora_test_http_client_response_headers
    network/iora_test_http_client_redirect_clamp_1xx
    network/iora_test_http_client_scheme_cache_key
    network/iora_test_http_client_exchange_deadline
    network/iora_test_http_client_retry
    network/iora_test_http_client_cancel
    network/iora_test_tcp_engine
    network/iora_test_tcp_engine_teardown_race
    network/iora_test_tcp_rapid_send
    network/iora_test_tcp_engine_timers
    network/iora_test_udp_engine
    network/iora_test_udp_engine_teardown_race
    network/iora_test_transport_improvements
    network/iora_test_webhook_transport
    network/iora_test_websocket_frame
    network/iora_test_websocket
    network/iora_test_transport
    network/iora_test_transport_sync_dscp_fixes
    network/iora_test_tls_identity
    network/iora_test_engine_introspection
    # Event-driven DNS-resolve tests (tracker 2026-09-06-4). The three below
    # monopolise the process-wide blockingIoPool() (block all workers / fill the
    # queue) to drive resolve-timeout and reject-fast paths deterministically, so
    # they are ISOLATED in their own binaries and ordered LAST in this list.
    network/iora_test_tcp_engine_resolve
    network/iora_test_udp_engine_resolve
    network/iora_test_name_resolver_saturation
)


# Core namespace tests
set(CORE_TESTS
    core/iora_test_blocking_queue
    core/iora_test_config_loader
    core/iora_test_config_loader_get_table
    core/iora_test_config_loader_get_table_array
    core/iora_test_event_queue
    core/iora_test_external_logger
    core/iora_test_logger
    core/iora_test_logger_external_handler_race
    core/iora_test_logger_self_clear_deadlock
    core/iora_test_logger_format_snapshot
    core/iora_test_logger_handler_file_restore
    core/iora_test_logger_immortal_scenario1_exit_from_handler
    core/iora_test_logger_immortal_scenario2_static_sink_dtor
    core/iora_test_logger_immortal_exit_flush
    core/iora_test_threadpool
    core/iora_test_threadpool_cleanup
    core/iora_test_threadpool_lifecycle
    core/iora_test_async_pool
    core/iora_test_async_pool_crossso
    core/iora_test_timer
    core/iora_test_timer_lifecycle
    core/iora_test_metrics
    core/iora_test_result
    core/iora_test_string_utils
    core/iora_test_buffer_view
    core/iora_test_ring_buffer
    core/iora_test_concurrent_hash_map
    core/iora_test_state_machine
    core/iora_test_signal
    core/iora_test_rate_limiter
    core/iora_test_timing_wheel
    core/iora_test_timing_wheel_lifecycle
    core/iora_test_timing_wheel_reset_ndebug
)

# Parsers namespace tests
set(PARSERS_TESTS
    parsers/iora_test_json_parser
    parsers/iora_test_xml_parser
    parsers/iora_test_minimal_toml_serializer_array_of_tables
    parsers/iora_test_minimal_toml_parser_malformed
    parsers/iora_test_http_header_combining
    parsers/iora_test_http_message_hardening
    parsers/iora_test_accept_encoding
    parsers/iora_test_content_coding
)

# Util namespace tests
set(UTIL_TESTS
    util/iora_test_crc32
    util/iora_test_gzip
    util/iora_test_gzip_decode
    util/iora_test_expiring_cache
    util/iora_test_shell_runner
    util/iora_test_ttl_map
)

# Storage namespace tests
set(STORAGE_TESTS
    storage/iora_test_state
    storage/iora_test_kvstore
)

# Service/Plugin system tests
set(SERVICE_TESTS
    service/iora_test_iora_service
    service/iora_test_plugin
    service/iora_test_plugin_drain
    service/iora_test_plugin_dependencies
    service/iora_test_plugin_isolation
    service/iora_test_features_config
    service/iora_test_api_module_reverse_map
    service/iora_test_callexportedapi_gating
    service/iora_test_loadfailure_teardown
    service/iora_test_unload_teardown_exception
    service/iora_test_validate_module_path
)

# Debug/helper tests (keep in root)
set(DEBUG_TESTS
    debug_chained_test
    simple_chained_test
)

# Web namespace tests (ServiceRegistry, middleware interfaces, HTMX support)
set(WEB_TESTS
    web/test_service_registry
    web/test_service_registry_concurrency
    web/test_service_registry_crossso
    web/test_html_escape
    web/test_mustache
    web/test_routing_extensions
    web/test_base64_decode
    web/test_http_auth
    web/test_assets
    web/test_sse_stream
    web/test_channels
    web/test_channels_concurrency
    web/test_sse_integration
    web/test_application_integration
    web/test_htmx_helpers
    web/test_websocket_reconnect
)

# RPC namespace tests (tracker 2026-07-26-1). EXTENSION-LESS entries: the
# registration loop appends ".cpp" and guards with if(EXISTS ...); a ".cpp"
# suffix here yields "...cpp.cpp", EXISTS is false, and the entry is SILENTLY
# skipped. At phase-2 this list carries ONLY the four base targets whose .cpp
# files exist by phase-2. The C1-port targets (client_pool, gzip_request,
# gzip_response, and the standalone quiesce/self-destruct executable) are
# registered by their own phase-6 tasks (6.5/6.6/6.7) once those files exist.
set(RPC_TESTS
    rpc/iora_test_jsonrpc_server
    rpc/iora_test_jsonrpc_http
    rpc/iora_test_jsonrpc_client
    rpc/iora_test_jsonrpc_e2e
    # task-6.7: the client gzip-config foundation unit test (pure unit; its one
    # former plugin case is rewritten to a direct JsonRpcHttpOptions defaults check).
    rpc/iora_test_jsonrpc_gzip_foundation
    # task-6.7: request-direction gzip (server side composes HttpServer +
    # JsonRpcServer + JsonRpcHttpEndpoint; carries the _requestCompressionMutex probe).
    rpc/iora_test_jsonrpc_gzip_request
    # task-6.7: response-direction gzip (server compresses + Vary; client decodes).
    rpc/iora_test_jsonrpc_gzip_response
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
if(IORA_BUILD_WEB_TESTS)
    list(APPEND ALL_TESTS ${WEB_TESTS})
endif()
if(IORA_BUILD_RPC_TESTS)
    list(APPEND ALL_TESTS ${RPC_TESTS})
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

# task-1.4 carrier-agnostic invariant probe (registered by task-2.1): a
# COMPILE-ONLY object-library target whose TU includes ONLY
# iora/rpc/jsonrpc_server.hpp. It has no main() and is never run — building it
# (cmake --build build --target iora_test_jsonrpc_standalone_include) proves the
# protocol header compiles standalone. Not an add_test; not in ALL_TESTS.
if(IORA_BUILD_RPC_TESTS AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rpc/iora_test_jsonrpc_standalone_include.cpp")
    add_library(iora_test_jsonrpc_standalone_include OBJECT
        rpc/iora_test_jsonrpc_standalone_include.cpp)
    configure_iora_target(iora_test_jsonrpc_standalone_include ENABLE_OPENSSL)
endif()

# task-6.6 (C1): the standalone self-destruct -> std::terminate executable, ported
# from src/modules/connectors/jsonrpc_client/tests/. A std::terminate takes down
# the whole process, so it CANNOT be a Catch2 case in the shared rpc binary — it
# is a STANDALONE executable whose scenarios are selected by argv[1], each
# registered as its own ctest with PASS/FAIL_REGULAR_EXPRESSION (the flat
# RPC_TESTS list cannot express these). Sanitizer flags come from the shared
# IORA_SANITIZED_TEST_TARGETS loop below (the target is on that list), so the
# target must be created here, before that loop runs.
if(IORA_BUILD_RPC_TESTS AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rpc/iora_test_jsonrpc_quiesce_selfdestruct.cpp")
    create_iora_test_target(iora_test_jsonrpc_quiesce_selfdestruct
        SOURCES rpc/iora_test_jsonrpc_quiesce_selfdestruct.cpp)
    target_include_directories(iora_test_jsonrpc_quiesce_selfdestruct PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR})
    # WHY EVERY SCENARIO CARRIES A PASS_REGULAR_EXPRESSION (cpp17 L-6): the shared
    # set_terminate handler _Exit(0)s on ANY terminate, so the exit code alone
    # cannot tell "the self-destruct detector fired" from "something else
    # terminated the process". Each positive scenario stamps a STAGE around the
    # reset that must terminate and the handler echoes it, so matching the stage
    # is what makes exit 0 mean the right thing. FAIL_REGULAR_EXPRESSION on
    # "FAILURE" takes precedence over the pass regex, so a diagnostic the scenario
    # prints on a wrong outcome can never be matched past. The configurer and
    # enqfail scenarios deadlock in quiesce STEP 3 on a regression and hang to the
    # TIMEOUT; only `selfdestruct` can reach its `return 1`.
    add_test(NAME rpc::jsonrpc_quiesce_selfdestruct
        COMMAND iora_test_jsonrpc_quiesce_selfdestruct)
    set_tests_properties(rpc::jsonrpc_quiesce_selfdestruct PROPERTIES TIMEOUT 60
        PASS_REGULAR_EXPRESSION "self-destruct detected\\) stage=own-callback"
        FAIL_REGULAR_EXPRESSION "FAILURE")
    add_test(NAME rpc::jsonrpc_quiesce_otherclient_no_terminate
        COMMAND iora_test_jsonrpc_quiesce_selfdestruct otherclient)
    set_tests_properties(rpc::jsonrpc_quiesce_otherclient_no_terminate PROPERTIES TIMEOUT 60
        PASS_REGULAR_EXPRESSION "per-Impl isolation holds"
        FAIL_REGULAR_EXPRESSION "FAILURE")
    add_test(NAME rpc::jsonrpc_quiesce_enqfail_selfdestruct
        COMMAND iora_test_jsonrpc_quiesce_selfdestruct enqfail)
    set_tests_properties(rpc::jsonrpc_quiesce_enqfail_selfdestruct PROPERTIES TIMEOUT 60
        PASS_REGULAR_EXPRESSION "self-destruct detected\\) stage=enqueue-failure-delivery"
        FAIL_REGULAR_EXPRESSION "FAILURE")
    add_test(NAME rpc::jsonrpc_quiesce_configurer_selfdestruct
        COMMAND iora_test_jsonrpc_quiesce_selfdestruct configurer)
    set_tests_properties(rpc::jsonrpc_quiesce_configurer_selfdestruct PROPERTIES TIMEOUT 60
        PASS_REGULAR_EXPRESSION "self-destruct detected\\) stage=configurer-window"
        FAIL_REGULAR_EXPRESSION "FAILURE")
endif()

# task-6.5 (C1): the inherited pool concurrency suite, ported from
# src/modules/connectors/jsonrpc_client/tests/. It uses FIXED loopback ports
# (18150-18189) in its LatchedHttpServer / RawCaptureServer fixtures, so every
# registration is RESOURCE_LOCK'd on a shared token. The default registration runs
# the GREEN tag set; the four CR repros run as their own focused regression guards.
# Created here (before the IORA_SANITIZED_TEST_TARGETS loop, to which it is added)
# because the tag-filtered default + per-repro registrations cannot be expressed
# by the flat RPC_TESTS create_individual_test path.
if(IORA_BUILD_RPC_TESTS AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/rpc/iora_test_jsonrpc_client_pool.cpp")
    create_iora_test_target(iora_test_jsonrpc_client_pool
        SOURCES rpc/iora_test_jsonrpc_client_pool.cpp)
    target_include_directories(iora_test_jsonrpc_client_pool PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}) # iora_test_net_utils.hpp lives in tests/
    add_test(NAME rpc::iora_test_jsonrpc_client_pool
        COMMAND iora_test_jsonrpc_client_pool
        "[scaffold],[seam],[fixture],[phase4],[phase3],[phase5],[phase6],[phase7],[connecttimeout]")
    set_tests_properties(rpc::iora_test_jsonrpc_client_pool PROPERTIES
        TIMEOUT 180 RESOURCE_LOCK jsonrpc_pool_ports)
    # Per-repro standalone guards (CR-1..CR-4), each filtered to one Catch2 tag.
    add_test(NAME rpc::jsonrpc_client_pool_cr1_identity
        COMMAND iora_test_jsonrpc_client_pool "[cr1]")
    set_tests_properties(rpc::jsonrpc_client_pool_cr1_identity PROPERTIES
        TIMEOUT 60 RESOURCE_LOCK jsonrpc_pool_ports)
    add_test(NAME rpc::jsonrpc_client_pool_cr2_freed_pool
        COMMAND iora_test_jsonrpc_client_pool "[cr2]")
    set_tests_properties(rpc::jsonrpc_client_pool_cr2_freed_pool PROPERTIES
        TIMEOUT 60 RESOURCE_LOCK jsonrpc_pool_ports)
    add_test(NAME rpc::jsonrpc_client_pool_cr3_deadlock
        COMMAND iora_test_jsonrpc_client_pool "[cr3]")
    set_tests_properties(rpc::jsonrpc_client_pool_cr3_deadlock PROPERTIES
        TIMEOUT 60 RESOURCE_LOCK jsonrpc_pool_ports)
    add_test(NAME rpc::jsonrpc_client_pool_cr4_quiesce_waits
        COMMAND iora_test_jsonrpc_client_pool "[cr4]")
    set_tests_properties(rpc::jsonrpc_client_pool_cr4_quiesce_waits PROPERTIES
        TIMEOUT 60 RESOURCE_LOCK jsonrpc_pool_ports)
endif()

# Suppress a known GCC false-positive (-Wfree-nonheap-object) triggered by
# vector::reserve inlined from KVStore::writeLogEntry. Matches the suppression
# the former mod_kvstore target carried.
if(TARGET iora_test_kvstore)
    target_compile_options(iora_test_kvstore PRIVATE -Wno-free-nonheap-object)
endif()

# The aged-file compressor's test-injection seams (Logger::TestHooks) are compiled
# in ONLY for this test target — production/shipped builds of logger.hpp have no
# such fault-injection surface. See logger.hpp (IORA_ENABLE_TEST_HOOKS).
if(TARGET iora_test_logger)
    target_compile_definitions(iora_test_logger PRIVATE IORA_ENABLE_TEST_HOOKS)
endif()

# TimingWheel lifecycle/orphan tests need the header's test-injection seams
# (_testScheduleGate, testAdvanceCount) — compiled in ONLY for these targets;
# production builds of timing_wheel.hpp have none.
# The reset-ndebug target ALSO defines NDEBUG so the former debug-only reset()
# precondition assert is compiled out, proving the runtime CAS is the guard
# (tracker 2026-09-10-7 T4/R1).
if(TARGET iora_test_timing_wheel_lifecycle)
    target_compile_definitions(iora_test_timing_wheel_lifecycle
        PRIVATE IORA_TIMING_WHEEL_TEST_HOOKS)
endif()
if(TARGET iora_test_timing_wheel_reset_ndebug)
    target_compile_definitions(iora_test_timing_wheel_reset_ndebug
        PRIVATE IORA_TIMING_WHEEL_TEST_HOOKS NDEBUG)
endif()

# LoggerData-immortal probes (tracker 2026-07-23-4): each drives a process EXIT
# (std::exit from a handler, static-destruction ordering, or a forked child that
# exits). Their assertion is a CLEAN EXIT within a bounded time — a regression
# (teardown deadlock, hang, or crash) must fail via the TIMEOUT rather than wedge
# the suite. The scenario-1 probe loops the race, so it gets a larger budget.
set(IORA_LOGGER_IMMORTAL_PROBE_TESTS
    core::iora_test_logger_immortal_scenario1_exit_from_handler
    core::iora_test_logger_immortal_scenario2_static_sink_dtor
    core::iora_test_logger_immortal_exit_flush
)
foreach(_probe_test ${IORA_LOGGER_IMMORTAL_PROBE_TESTS})
    if(TEST ${_probe_test})
        set_tests_properties(${_probe_test} PROPERTIES TIMEOUT 60)
        # Under an ASan build these probes exercise the intentional immortal leak
        # and process-exit paths. LSan's exit-time StopTheWorld hangs on WSL2
        # (ptrace/internal_waitpid), so disable the leak check (the immortal is
        # reachable via a live static pointer and is not a real leak anyway), and
        # keep handle_segv=0 per the WSL2 ASan convention. detect_leaks=0 does NOT
        # disable use-after-free detection. Harmless in a non-ASan build.
        if(IORA_ENABLE_ASAN)
            set_tests_properties(${_probe_test} PROPERTIES
                ENVIRONMENT "ASAN_OPTIONS=handle_segv=0:detect_leaks=0")
        endif()
    endif()
endforeach()

# The callExportedApi drain-gate test (Slice B, tracker 2026-09-07-3) has
# self-unload / transitive / reentrant liveness cases: a drain-deadlock
# regression must FAIL via this TIMEOUT rather than wedge the suite. The worker-
# thread bounding inside the test detaches a hung call so the case fails on its
# own; this ctest TIMEOUT is the outer backstop (cpp17-1).
if(TEST service::iora_test_callexportedapi_gating)
    set_tests_properties(service::iora_test_callexportedapi_gating PROPERTIES TIMEOUT 120)
endif()

# The load-failure teardown test (tracker 2026-09-07-9, F-4) has a blocking-
# onLoad liveness case; a monolithic-hold regression that wedged a caller must
# FAIL via this TIMEOUT rather than hang the suite (the in-test bounded waits are
# the first line; this is the outer backstop).
if(TEST service::iora_test_loadfailure_teardown)
    set_tests_properties(service::iora_test_loadfailure_teardown PROPERTIES TIMEOUT 120)
endif()

# The unload-path teardown-exception test (trackers 2026-09-08-4 / -3) exercises
# onUnload/onDependencyUnloaded throw paths; a teardown/drain regression that
# wedged an unload must FAIL via this TIMEOUT rather than hang the suite.
if(TEST service::iora_test_unload_teardown_exception)
    set_tests_properties(service::iora_test_unload_teardown_exception PROPERTIES TIMEOUT 120)
endif()

# Apply the opt-in sanitizer to the concurrency-sensitive test targets. Each of
# these exercises header-only concurrency logic (TtlMap/TimerService, Transport
# + TCP/UDP engines, WebSocketClient reconnect worker, ExpiringCache purge
# thread) compiled directly into the test TU, so per-target instrumentation
# covers the race surface. Mirrors the IORA_ENABLE_TSAN/ASAN options above.
set(IORA_SANITIZED_TEST_TARGETS
    iora_test_timing_wheel
    iora_test_timing_wheel_lifecycle
    iora_test_timing_wheel_reset_ndebug
    iora_test_timer_lifecycle
    iora_test_plugin_drain
    iora_test_callexportedapi_gating
    iora_test_loadfailure_teardown
    iora_test_unload_teardown_exception
    iora_test_plugin
    iora_test_logger
    iora_test_gzip
    iora_test_gzip_decode
    iora_test_ttl_map
    iora_test_expiring_cache
    iora_test_transport
    iora_test_transport_improvements
    iora_test_tcp_engine
    iora_test_tcp_engine_teardown_race
    iora_test_udp_engine
    iora_test_udp_engine_teardown_race
    iora_test_name_resolver
    iora_test_tcp_engine_resolve
    iora_test_udp_engine_resolve
    iora_test_name_resolver_saturation
    iora_test_http_client_lease
    iora_test_http_client_response_framing
    iora_test_http_client_retry
    iora_test_http_client_cancel
    iora_test_logger_external_handler_race
    iora_test_logger_self_clear_deadlock
    iora_test_logger_format_snapshot
    iora_test_logger_handler_file_restore
    iora_test_logger_immortal_scenario1_exit_from_handler
    iora_test_logger_immortal_scenario2_static_sink_dtor
    iora_test_logger_immortal_exit_flush
    test_websocket_reconnect
    # rpc group (tracker 2026-07-26-1). The four base targets registered at
    # phase-2; the remaining C1-port targets (client_pool, gzip_request,
    # gzip_response) are appended by their own phase-6 tasks 6.5/6.7.
    iora_test_jsonrpc_server
    iora_test_jsonrpc_http
    iora_test_jsonrpc_client
    iora_test_jsonrpc_e2e
    # task-6.6: standalone self-destruct executable (created above, before this loop).
    iora_test_jsonrpc_quiesce_selfdestruct
    # task-6.7: gzip foundation unit test + request-direction (TSan probe) + response.
    iora_test_jsonrpc_gzip_foundation
    iora_test_jsonrpc_gzip_request
    iora_test_jsonrpc_gzip_response
    # task-6.5: inherited pool concurrency suite (created above, before this loop).
    iora_test_jsonrpc_client_pool
)
foreach(_san_target ${IORA_SANITIZED_TEST_TARGETS})
    if(TARGET ${_san_target})
        if(IORA_ENABLE_TSAN)
            message(STATUS "${_san_target}: ThreadSanitizer enabled")
            target_compile_options(${_san_target} PRIVATE -fsanitize=thread -g -O1)
            target_link_options(${_san_target} PRIVATE -fsanitize=thread)
        elseif(IORA_ENABLE_ASAN)
            message(STATUS "${_san_target}: AddressSanitizer enabled")
            target_compile_options(${_san_target} PRIVATE
                -fsanitize=address -fno-omit-frame-pointer -g -O1
                # Suppress a GCC 12 libstdc++ <regex> false positive surfaced by
                # ASan's -O1 in Catch2's test-name matching (not our code).
                -Wno-maybe-uninitialized)
            target_link_options(${_san_target} PRIVATE -fsanitize=address)
        endif()
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

if(IORA_BUILD_WEB_TESTS)
    add_custom_target(test_web COMMENT "Running web tests")
    foreach(test_path ${WEB_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_web POST_BUILD
                COMMAND ${test_name}
                COMMENT "Running ${test_name}"
                VERBATIM
            )
        endif()
    endforeach()
endif()

if(IORA_BUILD_RPC_TESTS)
    add_custom_target(test_rpc COMMENT "Running rpc tests")
    foreach(test_path ${RPC_TESTS})
        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${test_path}.cpp")
            get_filename_component(test_name ${test_path} NAME)
            add_custom_command(TARGET test_rpc POST_BUILD
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

    # The drain-redesign test (tracker 2026-09-07-1) dlopen's plugins at runtime,
    # so a targeted `cmake --build build --target iora_test_plugin_drain` must also
    # build the .so's it loads, and it needs libdl for dlopen. New drain-specific
    # test plugins are added under plugins/ and depended on here as they land.
    if(TARGET iora_test_plugin_drain)
        foreach(_drain_plugin testplugin exportthenthrowplugin onloadgetsafeplugin)
            if(TARGET ${_drain_plugin})
                add_dependencies(iora_test_plugin_drain ${_drain_plugin})
            endif()
        endforeach()
        target_link_libraries(iora_test_plugin_drain PRIVATE ${CMAKE_DL_LIBS})
    endif()

    # The api-module reverse-map test (tracker 2026-09-07-8) dlopen's plugins
    # at runtime; depend on them so a targeted build of the test also builds
    # the .so's it loads, and link libdl for dlopen.
    if(TARGET iora_test_api_module_reverse_map)
        foreach(_reverse_map_plugin testplugin collidepfxplugin collidepfxplusplugin
                nonconventionplugin identityexportplugin identityexportthenthrowplugin
                ownerplugin ownerconflictplugin)
            if(TARGET ${_reverse_map_plugin})
                add_dependencies(iora_test_api_module_reverse_map ${_reverse_map_plugin})
            endif()
        endforeach()
        target_link_libraries(iora_test_api_module_reverse_map PRIVATE ${CMAKE_DL_LIBS})
    endif()

    # The callExportedApi drain-gate test (Slice B, tracker 2026-09-07-3)
    # dlopen's plugins at runtime; depend on them so a targeted build of the
    # test also builds the .so's it loads, and link libdl for dlopen.
    if(TARGET iora_test_callexportedapi_gating)
        foreach(_gating_plugin testplugin slowapiplugin selfunloadplugin
                transitiveouterplugin transitiveinnerplugin reentrantselfplugin)
            if(TARGET ${_gating_plugin})
                add_dependencies(iora_test_callexportedapi_gating ${_gating_plugin})
            endif()
        endforeach()
        target_link_libraries(iora_test_callexportedapi_gating PRIVATE ${CMAKE_DL_LIBS})
    endif()

    # The load-failure teardown-hardening test (tracker 2026-09-07-9, F-4/S-2)
    # dlopen's plugins at runtime; depend on them so a targeted build of the
    # test also builds the .so's it loads, and link libdl for dlopen.
    if(TARGET iora_test_loadfailure_teardown)
        foreach(_lf_plugin testplugin blockingonloadplugin requiredepthenthrowplugin
                exportthenthrowplugin identityexportthenthrowplugin
                ctorexportplugin factorynullexportplugin factorythrowexportplugin
                nonstdonloadthrowplugin factorynonstdthrowexportplugin
                requiredepnonstdthrowplugin)
            if(TARGET ${_lf_plugin})
                add_dependencies(iora_test_loadfailure_teardown ${_lf_plugin})
            endif()
        endforeach()
        target_link_libraries(iora_test_loadfailure_teardown PRIVATE ${CMAKE_DL_LIBS})
    endif()

    # The unload-path teardown-exception test (trackers 2026-09-08-4 / -3)
    # dlopen's plugins at runtime; depend on them so a targeted build of the test
    # also builds the .so's it loads, and link libdl for dlopen.
    if(TARGET iora_test_unload_teardown_exception)
        foreach(_ut_plugin testplugin unloaddepnonstdthrowplugin unloaddeprecordplugin
                onunloadthrowstddeprecordplugin onunloadnonstdthrowplugin
                unloaddepstdthrowplugin onunloadrecordplugin)
            if(TARGET ${_ut_plugin})
                add_dependencies(iora_test_unload_teardown_exception ${_ut_plugin})
            endif()
        endforeach()
        target_link_libraries(iora_test_unload_teardown_exception PRIVATE ${CMAKE_DL_LIBS})
    endif()

    # The validateModulePath traversal-guard test (tracker 2026-09-10-12) copies
    # and loadSingleModule's testplugin.so from hidden/'..'-bearing paths at
    # runtime; depend on the plugin so a targeted build also builds the .so it
    # loads, and link libdl for dlopen.
    if(TARGET iora_test_validate_module_path)
        if(TARGET testplugin)
            add_dependencies(iora_test_validate_module_path testplugin)
        endif()
        target_link_libraries(iora_test_validate_module_path PRIVATE ${CMAKE_DL_LIBS})
    endif()
endif()

# Build core test plugins (generalAsyncPool cross-.so identity test, DP-9) when
# core tests are on. The test dlopen's the plugin at runtime; depend on it so a
# targeted build of the test also builds the .so, and link libdl for dlopen.
if(IORA_BUILD_CORE_TESTS)
    add_subdirectory(core_plugins)
    if(TARGET iora_test_async_pool_crossso AND TARGET core_test_async_pool_plugin)
        add_dependencies(iora_test_async_pool_crossso core_test_async_pool_plugin)
        target_link_libraries(iora_test_async_pool_crossso PRIVATE ${CMAKE_DL_LIBS})
    endif()
endif()

# Build web test plugins (ServiceRegistry cross-.so test) when web tests are on.
# Kept separate from the SERVICE-gated plugins/ so the cross-.so test plugin is
# present in a WEB-only configuration (-DIORA_BUILD_WEB_TESTS=ON).
if(IORA_BUILD_WEB_TESTS)
    add_subdirectory(web_plugins)
    # The cross-.so test dlopen's the plugin at runtime; make the test depend on
    # the plugin so a targeted build of the test also builds the .so.
    if(TARGET test_service_registry_crossso AND TARGET web_test_registry_plugin)
        add_dependencies(test_service_registry_crossso web_test_registry_plugin)
    endif()

    # Out-of-tree iora_embed_assets() consumer test (asset_pipeline H-6/R-14).
    # Hermetically installs the current build to a test-controlled prefix and
    # drives a real find_package(Iora) consumer (configure/build-bound, kept
    # serial with -j1 per the web-test convention).
    add_test(NAME web::test_embed_assets
        COMMAND ${CMAKE_COMMAND}
            -DIORA_BUILD_DIR=${CMAKE_BINARY_DIR}
            -DCONSUMER_SRC=${CMAKE_CURRENT_SOURCE_DIR}/web/cmake/test_embed_assets
            -DWORK_DIR=${CMAKE_CURRENT_BINARY_DIR}/embed_assets_work
            -P ${CMAKE_CURRENT_SOURCE_DIR}/web/cmake/run_embed_assets_test.cmake
    )
endif()