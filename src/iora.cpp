// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.

#include <iora/iora.hpp>
#include <iostream>
#include <csignal>

#define IORA_DEFAULT_CONFIG_FILE_PATH "/etc/iora.conf.d/iora.cfg"

/// \brief Print help message
  static void printHelp()
  {
    std::cout
        << "Iora Service Options:\n"
        << "  -h, --help                       Show this help message\n"
        << "  -c, --config <file>              Configuration file path\n"
        << "  -p, --port <port>                Server port (default: 8080)\n"
        << "  -s, --state-file <file>          State persistence file\n"
        << "  -l, --log-level <level>          Log level (trace, debug, info, "
           "warning, error, fatal)\n"
        << "  -f, --log-file <file>            Log file path\n"
        << "      --log-async                  Enable async logging\n"
        << "      --log-retention <days>       Log retention in days\n"
        << "      --log-time-format <format>   Log timestamp format\n"
        << "      --modules-dir <dir>          Modules directory\n"
        << "      --modules-auto-load          Auto-load modules\n"
        << "      --tls-cert <file>            TLS certificate file\n"
        << "      --tls-key <file>             TLS key file\n"
        << "      --tls-ca <file>              TLS CA file\n"
        << "      --tls-require-client-cert    Require client certificate for "
           "TLS (default: false)\n"
        << "      --threadpool-min <n>           Set thread pool minimum "
           "threads (default: 2)\n"
        << "      --threadpool-max <n>           Set thread pool maximum "
           "threads (default: 8)\n"
        << "      --threadpool-queue <n>         Set thread pool queue size "
           "(default: 128)\n"
        << "      --threadpool-idle-timeout <n>  Set thread pool idle timeout "
           "in seconds (default: 60)\n";
  }


/// \brief Parse command-line arguments into the internal config
  void parseCliArgs(int argc, char** argv, iora::IoraService::Config& config, std::unique_ptr<iora::core::ConfigLoader>& configLoader)
  {
    for (int i = 1; i < argc; ++i)
    {
      std::string arg = argv[i];
      if ((arg == "-p" || arg == "--port") && i + 1 < argc)
      {
        try
        {
          config.server.port = std::stoi(argv[++i]);
        }
        catch (const std::exception& e)
        {
          throw std::runtime_error("Invalid port number: " +
                                   std::string(argv[i]));
        }
      }
      else if ((arg == "-c" || arg == "--config") && i + 1 < argc)
      {
        config.configFile = argv[++i];
        configLoader = std::make_unique<iora::core::ConfigLoader>(config.configFile.value());
        IORA_LOG_INFO("Using config file: " + config.configFile.value());
      }
      else if ((arg == "-s" || arg == "--state-file") && i + 1 < argc)
      {
        config.state.file = argv[++i];
      }
      else if ((arg == "-l" || arg == "--log-level") && i + 1 < argc)
      {
        config.log.level = argv[++i];
      }
      else if ((arg == "-f" || arg == "--log-file") && i + 1 < argc)
      {
        config.log.file = argv[++i];
      }
      else if (arg == "--log-async")
      {
        config.log.async = true;
      }
      else if (arg == "--log-retention" && i + 1 < argc)
      {
        try
        {
          config.log.retentionDays = std::stoi(argv[++i]);
        }
        catch (const std::exception& e)
        {
          throw std::runtime_error("Invalid log retention days: " +
                                   std::string(argv[i]));
        }
      }
      else if (arg == "--log-time-format" && i + 1 < argc)
      {
        config.log.timeFormat = argv[++i];
      }
      else if (arg == "--modules-dir" && i + 1 < argc)
      {
        config.modules.directory = argv[++i];
      }
      else if (arg == "--modules-auto-load")
      {
        config.modules.autoLoad = true;
      }
      else if (arg == "--tls-cert" && i + 1 < argc)
      {
        config.server.tls.certFile = argv[++i];
      }
      else if (arg == "--tls-key" && i + 1 < argc)
      {
        config.server.tls.keyFile = argv[++i];
      }
      else if (arg == "--tls-ca" && i + 1 < argc)
      {
        config.server.tls.caFile = argv[++i];
      }
      else if (arg == "--tls-require-client-cert")
      {
        config.server.tls.requireClientCert = true;
      }
      else if (arg == "--threadpool-min" && i + 1 < argc)
      {
        try
        {
          config.threadPool.minThreads =
              static_cast<std::size_t>(std::stoi(argv[++i]));
        }
        catch (const std::exception& e)
        {
          throw std::runtime_error("Invalid threadpool min threads: " +
                                   std::string(argv[i]));
        }
      }
      else if (arg == "--threadpool-max" && i + 1 < argc)
      {
        try
        {
          config.threadPool.maxThreads =
              static_cast<std::size_t>(std::stoi(argv[++i]));
        }
        catch (const std::exception& e)
        {
          throw std::runtime_error("Invalid threadpool max threads: " +
                                   std::string(argv[i]));
        }
      }
      else if (arg == "--threadpool-queue" && i + 1 < argc)
      {
        try
        {
          config.threadPool.queueSize =
              static_cast<std::size_t>(std::stoi(argv[++i]));
        }
        catch (const std::exception& e)
        {
          throw std::runtime_error("Invalid threadpool queue size: " +
                                   std::string(argv[i]));
        }
      }
      else if (arg == "--threadpool-idle-timeout" && i + 1 < argc)
      {
        try
        {
          config.threadPool.idleTimeoutSeconds =
              std::chrono::seconds(std::stoi(argv[++i]));
        }
        catch (const std::exception& e)
        {
          throw std::runtime_error("Invalid threadpool idle timeout: " +
                                   std::string(argv[i]));
        }
      }
      else if (arg == "-h" || arg == "--help")
      {
        printHelp();
        std::exit(0);
      }
      else if (arg.length() > 0 && arg[0] == '-')
      {
        throw std::runtime_error("Unknown option: " + arg);
      }
    }
  }

  /// \brief Parse TOML configuration file
  void parseTomlConfig(iora::IoraService::Config& config, std::unique_ptr<iora::core::ConfigLoader>& configLoader)
  {
    try
    {
      if (!configLoader)
      {
        std::string defaultConfigFile;
#ifdef IORA_DEFAULT_CONFIG_FILE_PATH
        defaultConfigFile = IORA_DEFAULT_CONFIG_FILE_PATH;
#endif
        configLoader = std::make_unique<iora::core::ConfigLoader>(defaultConfigFile);
        IORA_LOG_INFO("Using default config file: " + defaultConfigFile);
      }
      configLoader->reload();
      if (!config.server.port.has_value())
      {
        if (auto portOpt = configLoader->getInt("iora.server.port"))
        {
          config.server.port = static_cast<int>(*portOpt);
        }
      }
      if (!config.state.file.has_value())
      {
        if (auto stateFileOpt = configLoader->getString("iora.state.file"))
        {
          config.state.file = *stateFileOpt;
        }
      }
      if (!config.log.level.has_value())
      {
        if (auto logLevelOpt = configLoader->getString("iora.log.level"))
        {
          config.log.level = *logLevelOpt;
        }
      }
      if (!config.log.file.has_value())
      {
        if (auto logFileOpt = configLoader->getString("iora.log.file"))
        {
          config.log.file = *logFileOpt;
        }
      }
      if (!config.log.async.has_value())
      {
        if (auto logAsyncOpt = configLoader->getBool("iora.log.async"))
        {
          config.log.async = *logAsyncOpt;
        }
      }
      if (!config.log.retentionDays.has_value())
      {
        if (auto retentionOpt = configLoader->getInt("iora.log.retentionDays"))
        {
          config.log.retentionDays = static_cast<int>(*retentionOpt);
        }
      }
      if (!config.log.timeFormat.has_value())
      {
        if (auto timeFormatOpt =
                configLoader->getString("iora.log.timeFormat"))
        {
          config.log.timeFormat = *timeFormatOpt;
        }
      }
      if (!config.modules.directory.has_value())
      {
        if (auto modulesDirOpt =
                configLoader->getString("iora.modules.directory"))
        {
          config.modules.directory = *modulesDirOpt;
        }
      }
      if (!config.modules.autoLoad.has_value())
      {
        if (auto autoLoadOpt = configLoader->getBool("iora.modules.autoLoad"))
        {
          config.modules.autoLoad = *autoLoadOpt;
        }
      }
      if (!config.server.tls.certFile.has_value())
      {
        if (auto certFileOpt =
                configLoader->getString("iora.server.tls.certFile"))
        {
          config.server.tls.certFile = *certFileOpt;
        }
      }
      if (!config.server.tls.keyFile.has_value())
      {
        if (auto keyFileOpt =
                configLoader->getString("iora.server.tls.keyFile"))
        {
          config.server.tls.keyFile = *keyFileOpt;
        }
      }
      if (!config.server.tls.caFile.has_value())
      {
        if (auto caFileOpt = configLoader->getString("iora.server.tls.caFile"))
        {
          config.server.tls.caFile = *caFileOpt;
        }
      }
      if (!config.server.tls.requireClientCert.has_value())
      {
        if (auto requireClientCertOpt =
                configLoader->getBool("iora.server.tls.requireClientCert"))
        {
          config.server.tls.requireClientCert = *requireClientCertOpt;
        }
      }
      if (!config.threadPool.minThreads.has_value())
      {
        if (auto minThreadsOpt =
                configLoader->getInt("iora.threadPool.minThreads"))
        {
          config.threadPool.minThreads =
              static_cast<std::size_t>(*minThreadsOpt);
        }
      }
      if (!config.threadPool.maxThreads.has_value())
      {
        if (auto maxThreadsOpt =
                configLoader->getInt("iora.threadPool.maxThreads"))
        {
          config.threadPool.maxThreads =
              static_cast<std::size_t>(*maxThreadsOpt);
        }
      }
      if (!config.threadPool.queueSize.has_value())
      {
        if (auto queueSizeOpt =
                configLoader->getInt("iora.threadPool.queueSize"))
        {
          config.threadPool.queueSize =
              static_cast<std::size_t>(*queueSizeOpt);
        }
      }
      if (!config.threadPool.idleTimeoutSeconds.has_value())
      {
        if (auto idleTimeoutOpt =
                configLoader->getInt("iora.threadPool.idleTimeoutSeconds"))
        {
          config.threadPool.idleTimeoutSeconds =
              std::chrono::seconds(*idleTimeoutOpt);
        }
      }
    }
    catch (const std::exception& e)
    {
      iora::core::Logger::warning("Failed to load TOML config: " +
                            std::string(e.what()));
    }
  }

  

int main(int argc, char** argv)
{
  try 
  {
    std::unique_ptr<iora::core::ConfigLoader> configLoader;
    iora::IoraService::Config config;
    parseCliArgs(argc, argv, config, configLoader);
    parseTomlConfig(config, configLoader);

    iora::IoraService::instanceRef().setConfigLoader(std::move(configLoader));

    // Initialize the IoraService with command-line arguments
    iora::IoraService::init(config);
    
    std::signal(SIGINT, 
      [](int) 
      {
        iora::IoraService::instanceRef().terminate();
      }
    );
    
    // Wait for termination
    iora::IoraService::instanceRef().waitForTermination();
  }
  catch (const std::exception& ex)
  {
    std::cerr << "Error initializing IoraService: " << ex.what() << std::endl;
    iora::IoraService::shutdown();
    return EXIT_FAILURE;
  }
  
  iora::IoraService::shutdown();
  return 0;
}