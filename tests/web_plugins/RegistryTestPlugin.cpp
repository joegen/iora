// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Test plugin for the ServiceRegistry cross-.so test. In onLoad it registers a
// concrete IFoo implementation via ServiceRegistry::set<IFoo>(impl,
// getIdentity()); the core-process test then retrieves it via get<IFoo>() and
// calls a virtual method across the .so boundary, proving storage-in-core (C-4)
// unifies the plugin's and the foundation's view of the registry. onUnload does
// nothing — the authoritative core-driven unregisterModule(pluginName) in
// IoraService::unloadSingleModule removes the registration before dlclose (C-5).

#include "iora/iora.hpp"

#include "web/registry_cross_so_iface.hpp"

#include <memory>
#include <string>

namespace
{
struct FooImpl : iora_web_crossso_test::IFoo
{
  int magic() const override { return 4242; }
  std::string name() const override { return "from-plugin"; }
};
} // namespace

class RegistryTestPlugin : public iora::IoraService::Plugin
{
public:
  explicit RegistryTestPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService * /*svc*/) override
  {
    iora::ServiceRegistry::set<iora_web_crossso_test::IFoo>(std::make_shared<FooImpl>(),
                                                            getIdentity());
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(RegistryTestPlugin)
