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

# Load-failure teardown-hardening probes (tracker 2026-09-07-9, F-4 / S-2)
create_iora_plugin_target(blockingonloadplugin
    SOURCES BlockingOnLoadPlugin.cpp
)
create_iora_plugin_target(requiredepthenthrowplugin
    SOURCES RequireDepThenThrowPlugin.cpp
)

# S-1 dlclose-site unexport + empty-identity probes (tracker 2026-09-08-2,
# FX-i/FX-ii/FX-iii). CtorExportPlugin uses IORA_DECLARE_PLUGIN (ctor throws ->
# null-instance branch); the two Factory* plugins are HAND-WRITTEN loadModule
# factories (FactoryNull -> null-instance branch, FactoryThrow -> outer catch).
create_iora_plugin_target(ctorexportplugin
    SOURCES CtorExportPlugin.cpp
)
create_iora_plugin_target(factorynullexportplugin
    SOURCES FactoryNullExportPlugin.cpp
)
create_iora_plugin_target(factorythrowexportplugin
    SOURCES FactoryThrowExportPlugin.cpp
)

# Load-failure NON-std::exception escape probes (tracker 2026-09-08-1, O-2 / D1).
# NonStdOnLoad -> outer catch(...) via inner-miss; FactoryNonStdThrow -> outer
# catch(...) direct; RequireDepNonStdThrow -> onDependencyLoaded non-std swallowed
# at Plugin::require() :2628 (FX-C1) and notifyDependentsOfLoad :1768 (FX-C2).
create_iora_plugin_target(nonstdonloadthrowplugin
    SOURCES NonStdOnLoadThrowPlugin.cpp
)
create_iora_plugin_target(factorynonstdthrowexportplugin
    SOURCES FactoryNonStdThrowExportPlugin.cpp
)
create_iora_plugin_target(requiredepnonstdthrowplugin
    SOURCES RequireDepNonStdThrowPlugin.cpp
)

# Unload-path teardown-exception probes (trackers 2026-09-08-4 / -3). D1 throws a
# non-std from onDependencyUnloaded; D2 records its notification; OnUnloadThrowStd
# is M-depends-on-testplugin whose onUnload throws std once (FX-U2 / MUT-U3);
# OnUnloadNonStd throws a non-std from onUnload once (FX-U3 / MUT-U2).
create_iora_plugin_target(unloaddepnonstdthrowplugin
    SOURCES UnloadDepNonStdThrowPlugin.cpp
)
create_iora_plugin_target(unloaddeprecordplugin
    SOURCES UnloadDepRecordPlugin.cpp
)
create_iora_plugin_target(onunloadthrowstddeprecordplugin
    SOURCES OnUnloadThrowStdDepRecordPlugin.cpp
)
create_iora_plugin_target(onunloadnonstdthrowplugin
    SOURCES OnUnloadNonStdThrowPlugin.cpp
)
create_iora_plugin_target(unloaddepstdthrowplugin
    SOURCES UnloadDepStdThrowPlugin.cpp
)
create_iora_plugin_target(onunloadrecordplugin
    SOURCES OnUnloadRecordPlugin.cpp
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

# callExportedApi drain-gate probes (Slice B, tracker 2026-09-07-3,
# architecture/iora/callexportedapi_gating.json T1/T2/T4/T6/T9)
create_iora_plugin_target(slowapiplugin
    SOURCES SlowApiPlugin.cpp
)
create_iora_plugin_target(selfunloadplugin
    SOURCES SelfUnloadPlugin.cpp
)
create_iora_plugin_target(transitiveouterplugin
    SOURCES TransitiveOuterPlugin.cpp
)
create_iora_plugin_target(transitiveinnerplugin
    SOURCES TransitiveInnerPlugin.cpp
)
create_iora_plugin_target(reentrantselfplugin
    SOURCES ReentrantSelfPlugin.cpp
)
