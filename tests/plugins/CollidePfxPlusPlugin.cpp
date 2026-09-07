// File: iora/tests/plugins/CollidePfxPlusPlugin.cpp
//
// A-T1 colliding-prefix regression (tracker 2026-09-07-8, backlog -4). See
// CollidePfxPlugin.cpp — this module's filename ("collidepfxplus.so") starts
// with the sibling's full filename prefix ("collidepfx"), so a naive
// prefix-match resolver could confuse the two. Its own export must still
// resolve to itself.
#include "iora/iora.hpp"

class CollidePfxPlusPlugin : public iora::IoraService::Plugin
{
public:
  explicit CollidePfxPlusPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "collidepfxplus.value", []() { return 222; });
  }

  void onUnload() override {}
};

IORA_DECLARE_PLUGIN(CollidePfxPlusPlugin)
