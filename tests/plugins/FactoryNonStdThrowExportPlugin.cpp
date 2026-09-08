// File: iora/tests/plugins/FactoryNonStdThrowExportPlugin.cpp
//
// FX-B (tracker 2026-09-08-1, O-2 — load-path non-std escape, outer-catch path).
// A hand-written loadModule factory exports a pluginName-keyed API via the
// identity-string overload then throws a NON-std::exception (`throw 42`) BEFORE
// loadSingleModule's inner try, so it reaches the OUTER handler directly. The
// std-only outer catch (iora.hpp:1317) misses it; the outer catch(...) must run
// cleanupPartialLoadLocked + dlclose before rethrowing. Only a hand-written
// factory can reach the outer path with a non-std (IORA_DECLARE_PLUGIN catches a
// std ctor throw -> nullptr -> null-instance branch; a non-std ctor throw would
// also reach the outer catch, so this factory form is the representative case).
#include "iora/iora.hpp"

extern "C" iora::IoraPlugin *loadModule(iora::IoraService *service)
{
  service->exportApi(std::string("factorynonstdthrowexportplugin.so"),
                     "factorynonstdthrowexport.add", [](int a, int b) { return a + b; });
  throw 42; // NON-std::exception from the factory -> loadSingleModule outer catch(...)
}
