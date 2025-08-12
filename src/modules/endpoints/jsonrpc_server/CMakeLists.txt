add_compile_options(-Wno-free-nonheap-object)

# Create the test plugin
create_iora_plugin_target(mod_jsonrpc_server
    SOURCES mod_jsonrpc_server.cpp
)

target_compile_options(mod_jsonrpc_server PRIVATE -Wno-free-nonheap-object)

# Install plugins to /usr/local/lib/iora/modules
install(TARGETS mod_jsonrpc_server
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/iora/modules
)

add_subdirectory(tests)
