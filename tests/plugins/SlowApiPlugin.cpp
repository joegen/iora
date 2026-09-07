// File: iora/tests/plugins/SlowApiPlugin.cpp
//
// Drain-gate probe (Slice B, tracker 2026-09-07-3). Exports "slowapi.call",
// whose lambda captures the plugin object (`this`) and reads a member AFTER a
// test-controlled spin — deterministically widening the in-flight window so a
// concurrent unload's teardown races the read. WITHOUT the drain the plugin
// object is destroyed during the spin and the read is a use-after-free (ASan);
// WITH the drain, teardown waits and the read is valid.
#include "iora/iora.hpp"

#include "gating_control.hpp"

#include <thread>

class SlowApiPlugin : public iora::IoraService::Plugin
{
public:
  explicit SlowApiPlugin(iora::IoraService *svc) : Plugin(svc) {}

  void onLoad(iora::IoraService *svc) override
  {
    svc->exportApi(*this, "slowapi.call",
                   [this](iora::test::SlowApiControl *c) -> int
                   {
                     _ctl = c;
                     c->phase.store(1); // now in-flight, inside this lambda
                     while (c->phase.load() < 2)
                     {
                       std::this_thread::yield();
                     }
                     // Read plugin-object state. The drain must keep `this` alive
                     // until this call returns; record whether onUnload beat us
                     // here (must be false under the drain) and the magic value.
                     c->unloadRanBeforeRead.store(_ctl->unloadRan.load());
                     const int m = _magic;
                     c->observedMagic.store(m);
                     return m;
                   });
  }

  void onUnload() override
  {
    if (_ctl)
    {
      _ctl->unloadRan.store(true);
    }
  }

private:
  int _magic = 0xABCD;
  iora::test::SlowApiControl *_ctl = nullptr;
};

IORA_DECLARE_PLUGIN(SlowApiPlugin)
