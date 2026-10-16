// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include "iora_cli_config.hpp"

#include <csignal>
#include <iora/iora.hpp>
#include <iostream>

// The installed iora.cfg path, set by src/CMakeLists.txt from the configure-time
// install prefix. Falls back to the library default when built without it.
#ifndef IORA_INSTALLED_CONFIG_FILE
#define IORA_INSTALLED_CONFIG_FILE IORA_DEFAULT_CONFIG_FILE_PATH
#endif

int main(int argc, char **argv)
{
  try
  {
    std::unique_ptr<iora::core::ConfigLoader> configLoader;
    iora::IoraService::Config config;
    parseCliArgs(argc, argv, config, configLoader);
    parseTomlConfig(config, configLoader, IORA_INSTALLED_CONFIG_FILE);

    // Note: we intentionally do NOT call setConfigLoader() on the pre-init
    // instance. init() below calls shutdown() which destroyInstance()s any
    // existing singleton, so a moved-in ConfigLoader would be discarded and
    // silently recreated by applyConfig() from config.configFile. Let
    // applyConfig() own the construction — the local configLoader above is
    // only used to drive parseTomlConfig() above.
    (void)configLoader;

    // Initialize the IoraService with command-line arguments
    iora::IoraService::init(config);

    std::signal(SIGINT, [](int) { iora::IoraService::instanceRef().terminate(); });

    // Wait for termination
    iora::IoraService::instanceRef().waitForTermination();
  }
  catch (const std::exception &ex)
  {
    std::cerr << "Error initializing IoraService: " << ex.what() << std::endl;
    iora::IoraService::shutdown();
    return EXIT_FAILURE;
  }

  iora::IoraService::shutdown();
  return 0;
}