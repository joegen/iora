// File: iora/tests/plugins/IdentityExportThenThrowPlugin.cpp
//
// A-T2(b) identity-overload teardown, LOAD-FAILURE path (tracker
// 2026-09-07-8, backlog -6, cpp17 H-1). Mirrors ExportThenThrowPlugin.cpp but
// exports via the exportApi(pluginIdentity, name, func) overload instead of
// the Plugin& overload, so it exercises the loadSingleModule load-failure
// cleanup's identity-overload gap: that cleanup used to iterate
// Plugin::_apiExports (never populated by the identity overload) and so never
// unexported this API before dlclose.
#include "iora/iora.hpp"
#include <stdexcept>

class IdentityExportThenThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit IdentityExportThenThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(getIdentity(), "identityexportthenthrow.add", [](int a, int b) { return a + b; });
    throw std::runtime_error("intentional onLoad failure after identity-overload exportApi");
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(IdentityExportThenThrowPlugin)
