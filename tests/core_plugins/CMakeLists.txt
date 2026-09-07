# CMake configuration for core test plugins (generalAsyncPool cross-.so test).

# create_iora_plugin_target builds a SHARED library (PREFIX "" -> <name>.so)
# configured like every iora plugin and linked against libiora_core.so, so its
# reference to iora::core::generalAsyncPool() resolves to the single definition
# in libiora_core.so -- the property the cross-.so identity test verifies.
create_iora_plugin_target(core_test_async_pool_plugin
    SOURCES AsyncPoolAddrPlugin.cpp
)
