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

# Singleton isolation probe plugin
create_iora_plugin_target(singletonprobe
    SOURCES SingletonProbePlugin.cpp
)

# Drain-redesign failure-path probes (tracker 2026-09-07-1, steps 4-8 C1 / DP-F)
create_iora_plugin_target(exportthenthrowplugin
    SOURCES ExportThenThrowPlugin.cpp
)
create_iora_plugin_target(onloadgetsafeplugin
    SOURCES OnLoadGetSafePlugin.cpp
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

# API-module reverse-map probes (tracker 2026-09-07-8,
# architecture/iora/api_module_reverse_map.json A-T1..A-T4)
create_iora_plugin_target(collidepfxplugin
    SOURCES CollidePfxPlugin.cpp
)
create_iora_plugin_target(collidepfxplusplugin
    SOURCES CollidePfxPlusPlugin.cpp
)
create_iora_plugin_target(nonconventionplugin
    SOURCES NonConventionPlugin.cpp
)
create_iora_plugin_target(identityexportplugin
    SOURCES IdentityExportPlugin.cpp
)
create_iora_plugin_target(identityexportthenthrowplugin
    SOURCES IdentityExportThenThrowPlugin.cpp
)
create_iora_plugin_target(ownerplugin
    SOURCES OwnerPlugin.cpp
)
create_iora_plugin_target(ownerconflictplugin
    SOURCES OwnerConflictPlugin.cpp
)
