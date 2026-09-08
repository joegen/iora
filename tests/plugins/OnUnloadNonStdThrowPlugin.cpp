// File: iora/tests/plugins/OnUnloadNonStdThrowPlugin.cpp
//
// FX-U3 module M (tracker 2026-09-08-4). M's onUnload throws a NON-std::exception
// (`throw 42`) EXACTLY once (armed via the control block). The widened teardown
// outer catch(...) must make this behave like a std onUnload throw:
// unloadSingleModule(M) returns FALSE without rethrowing. Under MUT-U2 (revert
// the teardown outer catch to std-only) the non-std escapes teardown and the
// unloadSingleModule catch(...) rethrows, so unloadSingleModule(M) THROWS — which
// the FX-U3 REQUIRE_NOTHROW discriminator catches (a tryUnload catch-all would
// erase this throw-vs-return distinction). Throws once so UnloadAllOnExit can
// still reclaim M on the cleanup pass.
#include "iora/iora.hpp"

#include "unload_teardown_control.hpp"

class OnUnloadNonStdThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit OnUnloadNonStdThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    auto getCtl = svc->getExportedApi<iora::test::UnloadTeardownControl *()>("test.unloadctl");
    _ctl = getCtl();
  }

  void onUnload() override
  {
    if (_ctl != nullptr && _ctl->armNonStdOnUnloadThrow.load() > 0)
    {
      _ctl->armNonStdOnUnloadThrow.fetch_sub(1);
      throw 42; // NON-std: caught by the widened teardown outer catch(...)
    }
  }

private:
  iora::test::UnloadTeardownControl *_ctl = nullptr;
};

IORA_DECLARE_PLUGIN(OnUnloadNonStdThrowPlugin)
