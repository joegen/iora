// File: iora/tests/plugins/CollidePfxPlugin.cpp
//
// A-T1 colliding-prefix regression (tracker 2026-09-07-8, backlog -4). Its
// module filename ("collidepfx.so") is itself a PREFIX of a sibling plugin's
// module filename (CollidePfxPlusPlugin -> "collidepfxplus.so"), and its
// exported API name shares that same prefix. Loaded together with the
// sibling, both APIs must resolve to their own (not each other's) owning
// module via the _apiToModule reverse map.
#include "iora/iora.hpp"

class CollidePfxPlugin : public iora::IoraService::Plugin
{
public:
  explicit CollidePfxPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "collidepfx.value", []() { return 111; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(CollidePfxPlugin)
