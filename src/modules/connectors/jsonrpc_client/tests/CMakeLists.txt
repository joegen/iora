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
