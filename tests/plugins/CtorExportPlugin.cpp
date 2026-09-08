// File: iora/tests/plugins/CtorExportPlugin.cpp
//
// FX-i (tracker 2026-09-08-2, S-1 / defect_2). Exports an API from its
// CONSTRUCTOR — before loadSingleModule assigns _name (iora.hpp:1237, after the
// factory at :1234) — so getIdentity() is still empty and the export would key
// _apiToModule on "". The ctor then throws, so IORA_DECLARE_PLUGIN's factory
// catches it and returns nullptr, driving loadSingleModule's null-instance
// branch. Under Option A, exportApi rejects the empty identity (throws) so
// nothing is ever inserted; without it, the ""-keyed export dangles into the
// dlclosed .so (UAF at shutdown / getExportedApi) that removeExportsForModule
// (value == pluginName) can never reclaim.
#include "iora/iora.hpp"
#include <stdexcept>

class CtorExportPlugin : public iora::IoraService::Plugin
{
public:
  explicit CtorExportPlugin(iora::IoraService *svc) : Plugin(svc)
  {
    // _name is not yet set here -> getIdentity() is empty.
    svc->exportApi(*this, "ctorexport.add", [](int a, int b) { return a + b; });
    // Unreachable on the normal path: Option A makes the exportApi above throw
    // (empty identity), so the ctor already failed. This throw is load-bearing
    // only under the MUT-defect_2 mutant (empty-identity check removed): there
    // exportApi succeeds, and this throw drives the load into the null-instance
    // branch so the ""-keyed export dangles past dlclose (the ASan fault that
    // proves Option A is load-bearing).
    throw std::runtime_error("intentional ctor failure after empty-identity exportApi");
  }

  void onLoad(iora::IoraService *) override {}
  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(CtorExportPlugin)
