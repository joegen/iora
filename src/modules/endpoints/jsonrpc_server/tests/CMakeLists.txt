# JSON-RPC Server Module Tests

create_iora_test_target(iora_test_mod_jsonrpc_server
    SOURCES iora_test_mod_jsonrpc_server.cpp
)

target_include_directories(iora_test_mod_jsonrpc_server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Add the test to CTest
add_test(NAME JsonRpcServerModule COMMAND iora_test_mod_jsonrpc_server)

# Bound the suite so a re-entrancy/deadlock regression (the [jsonrpc][reentrancy]
# probe) is REAPED and reported as a CTest failure rather than hanging the run
# indefinitely (M-thread-1). The suite completes in a few seconds normally.
set_tests_properties(JsonRpcServerModule PROPERTIES TIMEOUT 120)