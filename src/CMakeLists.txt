add_executable(iora iora.cpp)

# Configure with common Iora settings, OpenSSL, and tiktoken support
configure_iora_target(iora 
    ENABLE_OPENSSL 
    ENABLE_TIKTOKEN
)

# Install the main iora application binary
install(TARGETS iora
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

add_subdirectory(modules/storage/kvstore)
add_subdirectory(modules/endpoints/jsonrpc_server)
add_subdirectory(modules/connectors/jsonrpc_client)