// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0

#ifndef IORA_CORE_SHARED
#error "IORA_CORE_SHARED must come from the iora_core target"
#endif

#include <iora/core/metrics.hpp>

int main()
{
  iora::core::MetricsRegistry::instance().setMaxSeries(100);
  return 0;
}
