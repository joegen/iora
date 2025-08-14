# JSON-RPC Client Module Tests
add_compile_options(-Wno-free-nonheap-object)


# Create functional test that actually exercises the client implementation
add_executable(iora_test_mod_jsonrpc_client_functional
    iora_test_mod_jsonrpc_client_functional.cpp
)

target_link_libraries(iora_test_mod_jsonrpc_client_functional
    PRIVATE
    ${CMAKE_DL_LIBS}
)

target_compile_options(iora_test_mod_jsonrpc_client_functional PRIVATE -Wno-free-nonheap-object)

# Create real client-server integration test with actual IoraService
create_iora_test_target(iora_test_mod_jsonrpc_client_server_real
    SOURCES iora_test_mod_jsonrpc_client_server_real.cpp
)

# Ensure both server and client plugins are built before this test
add_dependencies(iora_test_mod_jsonrpc_client_server_real 
    mod_jsonrpc_server 
    mod_jsonrpc_client
)

# Add tests to CTest
#if(ENABLE_TESTING)
    add_test(NAME JsonRpcClientFunctionalTest COMMAND iora_test_mod_jsonrpc_client_functional)
    add_test(NAME JsonRpcClientServerRealTest COMMAND iora_test_mod_jsonrpc_client_server_real)
#endif()