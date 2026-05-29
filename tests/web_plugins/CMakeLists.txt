# CMake configuration for web test plugins (ServiceRegistry cross-.so test).

# Cross-.so ServiceRegistry test plugin. create_iora_plugin_target builds a
# SHARED library configured like every other iora plugin (same toolchain,
# default visibility, RTTI) so the abiInvariant holds and type_index matches
# across the .so boundary.
create_iora_plugin_target(web_test_registry_plugin
    SOURCES RegistryTestPlugin.cpp
)

# Reach the shared cross-.so interface header at tests/web/.
target_include_directories(web_test_registry_plugin PRIVATE ${CMAKE_SOURCE_DIR}/tests)
