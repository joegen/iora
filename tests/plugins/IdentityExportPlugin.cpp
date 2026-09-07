// File: iora/tests/plugins/IdentityExportPlugin.cpp
//
// A-T2(a) identity-overload teardown, NORMAL unload (tracker 2026-09-07-8,
// backlog -6). Exports its API via the exportApi(pluginIdentity, name, func)
// overload (NOT the Plugin& overload), which the old Plugin::_apiExports-based
// teardown never saw -- the export would leak past dlclose and stay callable
// (use-after-dlclose). removeExportsForModule tears it down authoritatively
// via _apiToModule regardless of which overload registered it.
#include "iora/iora.hpp"

class IdentityExportPlugin : public iora::IoraService::Plugin
{
public:
  explicit IdentityExportPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(getIdentity(), "identityexport.value", []() { return 444; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(IdentityExportPlugin)
