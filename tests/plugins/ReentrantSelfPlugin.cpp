// File: iora/tests/plugins/ReentrantSelfPlugin.cpp
//
// Reentrant same-module probe (Slice B, tracker 2026-09-07-3, M1 multiset
// erase-one). "reenter.outer" calls "reenter.inner" of the SAME module, so the
// module is pushed onto this thread's in-flight multiset TWICE. When the inner
// call returns it must pop exactly ONE entry (erase(find), not erase(key) which
// removes both) so the module is STILL in-flight for the remainder of the outer
// call. To prove it, the outer call then attempts to unload its own module: the
// self-unload check must STILL catch it (throw), which "reenter.outer" reports
// as 1. With the erase(key) bug both entries would be gone, the self-unload
// check would miss, and unloadSingleModule would DEADLOCK on this thread's own
// in-flight count (caught by the test's bounded timeout).
#include "iora/iora.hpp"

class ReentrantSelfPlugin : public iora::IoraService::Plugin
{
public:
  explicit ReentrantSelfPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "reenter.inner", [this]() -> int { return 7; });

    svc->exportApi(*this, "reenter.outer",
                   [this]() -> int
                   {
                     // Nested call of the SAME module -> module pushed twice.
                     (void)service()->callExportedApi<int>("reenter.inner");
                     // Still inside the outer call: the module must remain
                     // in-flight (multiplicity preserved), so this self-unload
                     // must be caught.
                     bool selfUnloadCaught = false;
                     try
                     {
                       service()->unloadSingleModule(getIdentity());
                     }
                     catch (const std::exception &)
                     {
                       selfUnloadCaught = true;
                     }
                     return selfUnloadCaught ? 1 : 0;
                   });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(ReentrantSelfPlugin)
