// File: iora/tests/plugins/NonStdOnLoadThrowPlugin.cpp
//
// FX-A (tracker 2026-09-08-1, O-2 — load-path non-std escape). onLoad exports an
// API via the Plugin& overload (keyed on _name == the .so filename, set before
// onLoad) then throws a NON-std::exception (`throw 42`). The non-std misses the
// inner std-only catch (iora.hpp:1269) and must be caught by loadSingleModule's
// outer catch(...) (:1317), which runs cleanupPartialLoadLocked + dlclose before
// rethrowing — otherwise the export dangles (stale in _apiExports, the .so left
// mapped+registered) and the name is bricked. Under the MUT-1 mutant (outer
// catch(...) body removed) the non-std escapes both std-only catches and the
// export survives past dlclose.
#include "iora/iora.hpp"

class NonStdOnLoadThrowPlugin : public iora::IoraService::Plugin
{
public:
  explicit NonStdOnLoadThrowPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "nonstdonload.add", [](int a, int b) { return a + b; });
    throw 42; // NON-std::exception: escapes the std-only inner/outer catches
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(NonStdOnLoadThrowPlugin)
