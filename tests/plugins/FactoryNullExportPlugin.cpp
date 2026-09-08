// File: iora/tests/plugins/FactoryNullExportPlugin.cpp
//
// FX-ii (tracker 2026-09-08-2, S-1 / defect_1, cleanup path). A CUSTOM
// loadModule factory (not IORA_DECLARE_PLUGIN) that exports a pluginName-keyed
// API via the identity-string overload (identity == this .so's filename, the
// same key removeExportsForModule uses), then returns nullptr -> the
// null-instance branch. cleanupPartialLoadLocked(pluginName) must unexport it
// before the dlclose; without that, the export dangles into the unmapped .so.
#include "iora/iora.hpp"

extern "C" iora::IoraPlugin *loadModule(iora::IoraService *service)
{
  // Non-empty identity (accepted by Option A), keyed on the .so filename so the
  // pluginName-keyed cleanup at the null-instance branch can reclaim it.
  service->exportApi(std::string("factorynullexportplugin.so"), "factorynullexport.add",
                     [](int a, int b) { return a + b; });
  return nullptr; // -> loadSingleModule null-instance branch
}
