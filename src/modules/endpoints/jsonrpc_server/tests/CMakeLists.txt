# JSON-RPC Server Module Tests

create_iora_test_target(iora_test_mod_jsonrpc_server
    SOURCES iora_test_mod_jsonrpc_server.cpp
)

target_include_directories(iora_test_mod_jsonrpc_server PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Add the test to CTest
add_test(NAME JsonRpcServerModule COMMAND iora_test_mod_jsonrpc_server)