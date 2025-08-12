// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

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
    // Read config keys with prefix iora.modules.kvstore.
    std::string path = loader->getString("iora.modules.kvstore.path").value_or("kvstore.bin");
    KVStoreConfig config;
    if (auto v = loader->getInt("iora.modules.kvstore.max_log_size"))
      config.maxLogSizeBytes = static_cast<uint32_t>(*v);
    if (auto v = loader->getInt("iora.modules.kvstore.max_cache_size"))
      config.maxCacheSize = static_cast<uint32_t>(*v);
    if (auto v = loader->getBool("iora.modules.kvstore.background_compaction"))
      config.enableBackgroundCompaction = *v;
    if (auto v = loader->getInt("iora.modules.kvstore.compaction_interval_ms"))
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
    service->exportApi(*this, "kvstore.getString", [this](const std::string& key) -> std::optional<std::string> {
      return _store->getString(key);
    });
    service->exportApi(*this, "kvstore.setString", [this](const std::string& key, const std::string& value) -> void {
      _store->setString(key, value);
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
