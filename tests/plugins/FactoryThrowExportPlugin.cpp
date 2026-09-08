// File: iora/tests/plugins/FactoryThrowExportPlugin.cpp
//
// FX-iii (tracker 2026-09-08-2, S-1 / defect_1, outer-catch path). A CUSTOM
// loadModule factory that exports a pluginName-keyed API via the identity-string
// overload then THROWS a std::exception -> loadSingleModule's OUTER catch (the
// factory runs before the inner try, so the inner catch never sees it). Only a
// hand-written factory can reach the outer catch: IORA_DECLARE_PLUGIN catches a
// ctor throw and returns nullptr (the null-instance branch instead).
// cleanupPartialLoadLocked(pluginName) at the outer catch must unexport before
// the dlclose.
#include "iora/iora.hpp"
#include <stdexcept>

extern "C" iora::IoraPlugin *loadModule(iora::IoraService *service)
{
  service->exportApi(std::string("factorythrowexportplugin.so"), "factorythrowexport.add",
                     [](int a, int b) { return a + b; });
  throw std::runtime_error("intentional factory failure after exportApi");
}
