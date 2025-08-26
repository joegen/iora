# CMake configuration for test plugins

# Create the test plugin
create_iora_plugin_target(testplugin
    SOURCES TestPlugin.cpp
)

# Create dependency test plugins
create_iora_plugin_target(baseplugin
    SOURCES BasePlugin.cpp
)

create_iora_plugin_target(dependentplugin
    SOURCES DependentPlugin.cpp
)

create_iora_plugin_target(chainedplugin
    SOURCES ChainedPlugin.cpp
)

# Create cycle test plugins
create_iora_plugin_target(cycleplugina
    SOURCES CyclePluginA.cpp
)

create_iora_plugin_target(cyclepluginb
    SOURCES CyclePluginB.cpp
)

create_iora_plugin_target(cyclepluginc
    SOURCES CyclePluginC.cpp
)

# Indirect cycle test plugins
create_iora_plugin_target(indirectcyclea
    SOURCES IndirectCycleA.cpp
)

create_iora_plugin_target(indirectcycleb
    SOURCES IndirectCycleB.cpp
)

create_iora_plugin_target(indirectcyclec
    SOURCES IndirectCycleC.cpp
)