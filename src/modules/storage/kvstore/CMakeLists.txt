add_compile_options(-Wno-free-nonheap-object)

# Create the test plugin
create_iora_plugin_target(mod_kvstore
    SOURCES mod_kvstore.cpp
)

target_compile_options(mod_kvstore PRIVATE -Wno-free-nonheap-object)

# Install plugins to /usr/local/lib/iora/modules
install(TARGETS mod_kvstore
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/iora/modules
)

# Only build module tests if service tests are enabled
if(IORA_BUILD_SERVICE_TESTS OR IORA_BUILD_ALL_TESTS)
    add_subdirectory(tests)
endif()
