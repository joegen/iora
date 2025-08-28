add_compile_options(-Wno-free-nonheap-object)

# Create the test plugin
create_iora_plugin_target(mod_jsonrpc_client
    SOURCES mod_jsonrpc_client.cpp
)

target_compile_options(mod_jsonrpc_client PRIVATE -Wno-free-nonheap-object)

# Install plugins to /usr/local/lib/iora/modules
install(TARGETS mod_jsonrpc_client
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/iora/modules
)

# Only build module tests if service tests are enabled
if(IORA_BUILD_SERVICE_TESTS OR IORA_BUILD_ALL_TESTS)
    add_subdirectory(tests)
endif()
