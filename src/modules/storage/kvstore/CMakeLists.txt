add_compile_options(-Wno-free-nonheap-object)

# Create the test plugin
create_iora_plugin_target(mod_kvstore
    SOURCES mod_kvstore.cpp
)

target_compile_options(mod_kvstore PRIVATE -Wno-free-nonheap-object)

add_subdirectory(tests)
