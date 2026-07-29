# JSON-RPC Client Module Tests
add_compile_options(-Wno-free-nonheap-object)

# Create real client-server integration test with actual IoraService
create_iora_test_target(iora_test_mod_jsonrpc_client_server_real
    SOURCES iora_test_mod_jsonrpc_client_server_real.cpp
)

# Ensure both server and client plugins are built before this test
add_dependencies(iora_test_mod_jsonrpc_client_server_real 
    mod_jsonrpc_server 
    mod_jsonrpc_client
)

add_test(NAME JsonRpcClientServerRealTest COMMAND iora_test_mod_jsonrpc_client_server_real)

# ---------------------------------------------------------------------------
# Pool lifetime / identity defect repros (tracker 2026-07-26-2, phase 1).
# Constructs JsonRpcClient directly, so it includes jsonrpc_client.hpp from the
# parent module directory (task-1.1(f)).
# ---------------------------------------------------------------------------
create_iora_test_target(iora_test_jsonrpc_client_pool
    SOURCES iora_test_jsonrpc_client_pool.cpp
)

# jsonrpc_client.hpp lives one directory up; add it to the include path so the
# test can include it by bare name.
target_include_directories(iora_test_jsonrpc_client_pool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Opt-in sanitizer instrumentation. IORA_ENABLE_TSAN / IORA_ENABLE_ASAN are
# cache-global option()s (tests/CMakeLists.txt:41-42), readable from this module
# scope. This target is NOT reachable via IORA_SANITIZED_TEST_TARGETS: that list
# is consumed by a foreach guarded by if(TARGET ...) in tests/CMakeLists.txt,
# which runs from add_subdirectory(tests) BEFORE add_subdirectory(src), so this
# target does not yet exist there and appending its name is a silent no-op
# (task-1.1(c)). TSan and ASan are mutually exclusive; TSan takes precedence.
if(IORA_ENABLE_TSAN)
    message(STATUS "iora_test_jsonrpc_client_pool: ThreadSanitizer enabled")
    target_compile_options(iora_test_jsonrpc_client_pool PRIVATE -fsanitize=thread -g -O1)
    target_link_options(iora_test_jsonrpc_client_pool PRIVATE -fsanitize=thread)
elseif(IORA_ENABLE_ASAN)
    message(STATUS "iora_test_jsonrpc_client_pool: AddressSanitizer enabled")
    target_compile_options(iora_test_jsonrpc_client_pool PRIVATE
        -fsanitize=address -fno-omit-frame-pointer -g -O1
        -Wno-maybe-uninitialized)
    target_link_options(iora_test_jsonrpc_client_pool PRIVATE -fsanitize=address)
endif()

# Default registration runs ONLY the infrastructure cases (scaffold + seam),
# which pass at HEAD, so a normal ctest run stays green while the four repros
# remain deliberately RED (task-1.1(i): TEST name == TARGET name).
add_test(NAME iora_test_jsonrpc_client_pool
    COMMAND iora_test_jsonrpc_client_pool "[scaffold],[seam],[fixture]")
# RESOURCE_LOCK serializes the fixture's fixed-port (18150) bind against any
# other test that might claim it, independent of the -j1 convention (M2).
set_tests_properties(iora_test_jsonrpc_client_pool PROPERTIES
    TIMEOUT 60 RESOURCE_LOCK jsonrpc_pool_ports)

# --- Per-repro registrations (task-1.1(h)) -------------------------------
# Each runs the same binary filtered to one repro's Catch2 tag. The four differ
# in pre-fix signal, so their registration properties differ.

# CR-1 (task-1.4): the assertion half FAILS at HEAD (identity swap). DISABLED
# until task-4.1c makes release identity-based, which flips it GREEN.
add_test(NAME jsonrpc_client_pool_cr1_identity
    COMMAND iora_test_jsonrpc_client_pool "[cr1]~[.crash]")
set_tests_properties(jsonrpc_client_pool_cr1_identity PROPERTIES
    TIMEOUT 60 DISABLED TRUE)

# CR-3 (task-1.6): a re-entrant configurer DEADLOCKS the client. A DISABLED test
# is never executed, so it can never itself expire ctest's TIMEOUT (task-1.1(h),
# corrected for this repro in task-1.6): its pre-fix evidence is captured out of
# band via `timeout 60 ./iora_test_jsonrpc_client_pool "<cr3 case>"` (exit 124).
add_test(NAME jsonrpc_client_pool_cr3_deadlock
    COMMAND iora_test_jsonrpc_client_pool "[cr3]")
set_tests_properties(jsonrpc_client_pool_cr3_deadlock PROPERTIES
    TIMEOUT 60 DISABLED TRUE)

# CR-2 (task-1.5) and CR-4 (task-1.7): heap-use-after-free, deterministic ONLY
# under AddressSanitizer. Under ASan the fault aborts the process (_exit(1)), so
# WILL_FAIL inverts the verdict to a pass while the bug lives; the fix retires
# WILL_FAIL. Without ASan the UAF is silent UB, so register DISABLED — visible
# but never run without the detector. Each runs in isolation (a single-case
# filter) because the first ASan abort kills the process.
if(IORA_ENABLE_ASAN)
    add_test(NAME jsonrpc_client_pool_cr2_freed_pool
        COMMAND iora_test_jsonrpc_client_pool "[cr2]")
    set_tests_properties(jsonrpc_client_pool_cr2_freed_pool PROPERTIES
        TIMEOUT 90 WILL_FAIL TRUE
        ENVIRONMENT "ASAN_OPTIONS=handle_segv=0:detect_leaks=0:abort_on_error=0:disable_coredump=1")
    add_test(NAME jsonrpc_client_pool_cr4_freed_client
        COMMAND iora_test_jsonrpc_client_pool "[cr4]")
    set_tests_properties(jsonrpc_client_pool_cr4_freed_client PROPERTIES
        TIMEOUT 90 WILL_FAIL TRUE
        ENVIRONMENT "ASAN_OPTIONS=handle_segv=0:detect_leaks=0:abort_on_error=0:disable_coredump=1")
else()
    add_test(NAME jsonrpc_client_pool_cr2_freed_pool
        COMMAND iora_test_jsonrpc_client_pool "[cr2]")
    set_tests_properties(jsonrpc_client_pool_cr2_freed_pool PROPERTIES DISABLED TRUE)
    add_test(NAME jsonrpc_client_pool_cr4_freed_client
        COMMAND iora_test_jsonrpc_client_pool "[cr4]")
    set_tests_properties(jsonrpc_client_pool_cr4_freed_client PROPERTIES DISABLED TRUE)
endif()
