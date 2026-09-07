// File: iora/tests/plugins/ExportThenThrowPlugin.cpp
//
// onLoad exports an API and THEN throws — exercises loadSingleModule's failure
// path (C1): the exported plugin std::function must be unexported (destroyed while
// the .so is still mapped) before dlclose, or it dangles into the unmapped .so and
// faults at the next call / at ~IoraService. Run the load-then-shutdown under ASan.
#include "iora/iora.hpp"
#include <stdexcept>

class ExportThenThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit ExportThenThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "exportthenthrow.add", [](int a, int b) { return a + b; });
    throw std::runtime_error("intentional onLoad failure after exportApi");
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(ExportThenThrowPlugin)
