#include "iora/iora.hpp"

class SingletonProbePlugin : public iora::IoraService::Plugin
{
public:
  explicit SingletonProbePlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "probe.loggerAddr",
                   []() -> std::uint64_t
                   { return reinterpret_cast<std::uint64_t>(&iora::core::Logger::getData); });

    svc->exportApi(*this, "probe.serviceAddr",
                   []() -> std::uint64_t
                   { return reinterpret_cast<std::uint64_t>(&iora::IoraService::getInstancePtr); });

    // The frozen-inflight drain selects its self-tearer vs external branch on
    // Logger::handlerReentryDepth()'s thread_local (tracker 2026-07-21-3), so the
    // R-12 invariant the drain depends on is: the thread_local
    // INSTANCE must be one object process-wide. Probe the instance, not the
    // function symbol — the symbol is not the invariant (a header-inline member
    // can be emitted per-.so under optimization while the thread_local still
    // merges). Called on the caller's thread, so both sides compare the same
    // thread's instance.
    svc->exportApi(*this, "probe.handlerReentryDepthInstanceAddr",
                   []() -> std::uint64_t
                   { return reinterpret_cast<std::uint64_t>(&iora::core::Logger::handlerReentryDepth()); });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(SingletonProbePlugin)
