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
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(SingletonProbePlugin)
