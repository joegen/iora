#include "iora/iora.hpp"
#include "kvstore.hpp"
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>


class KVStorePlugin : public iora::IoraService::Plugin
{
public:
  explicit KVStorePlugin(iora::IoraService* service)
    : Plugin(service)
  {
    auto* loader = service->configLoader().get();
    if (!loader)
    {
      throw std::runtime_error("KVStorePlugin: configLoader is not available");
    }
    // Read config keys with prefix iora.kvstore.
    std::string path = loader->getString("iora.kvstore.path").value_or("kvstore.bin");
    KVStoreConfig config;
    if (auto v = loader->getInt("iora.kvstore.max_log_size"))
      config.maxLogSizeBytes = static_cast<uint32_t>(*v);
    if (auto v = loader->getInt("iora.kvstore.max_cache_size"))
      config.maxCacheSize = static_cast<uint32_t>(*v);
    if (auto v = loader->getBool("iora.kvstore.background_compaction"))
      config.enableBackgroundCompaction = *v;
    if (auto v = loader->getInt("iora.kvstore.compaction_interval_ms"))
      config.compactionInterval = std::chrono::milliseconds(*v);
    _store = std::make_unique<KVStore>(path, config);
  }

  void onLoad(iora::IoraService* service) override
  {
    // Export API: get, set, setBatch, getBatch
    service->exportApi(*this, "kvstore.get", [this](const std::string& key) -> std::optional<std::vector<std::uint8_t>> {
      return _store->get(key);
    });
    service->exportApi(*this, "kvstore.set", [this](const std::string& key, const std::vector<std::uint8_t>& value) -> void {
      _store->set(key, value);
    });
    service->exportApi(*this, "kvstore.setBatch", [this](const std::unordered_map<std::string, std::vector<std::uint8_t>>& batch) -> void {
      _store->setBatch(batch);
    });
    service->exportApi(*this, "kvstore.getBatch", [this](const std::vector<std::string>& keys) -> std::unordered_map<std::string, std::vector<std::uint8_t>> {
      return _store->getBatch(keys);
    });
  }

  void onUnload() override
  {
    if (_store)
    {
      _store->flush();
      _store.reset();
    }
  }

private:
  std::unique_ptr<KVStore> _store;
};


IORA_DECLARE_PLUGIN(KVStorePlugin);
