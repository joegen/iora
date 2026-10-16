// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public License 2.0.
// See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for details.
//
// Tests for the iora executable's config parsing (src/iora_cli_config.hpp) against
// the shipped template src/config/iora.cfg.in, and for IoraService::loadModules()
// continuing past a module that fails to load (tracker 2026-09-24-16).
//
// Harness rules: this file runs as one process with one IoraService singleton.
// Every scenario uses its own fresh subdir of one sandbox under the executable
// directory, runs exactly one init() with an AutoServiceShutdown right after it,
// and never keeps an instanceRef() across an init() or the shutdown guard.

#define CATCH_CONFIG_MAIN
#include "test_helpers.hpp"
#include <catch2/catch.hpp>

#include "iora_cli_config.hpp"

#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace
{
namespace fs = std::filesystem;

const fs::path &sandboxRoot()
{
  static const fs::path root = fs::path(iora::util::getExecutableDir()) / "cfgkeys_sandbox";
  return root;
}

// Removes the sandbox when the TEST_CASE ends (declared first, so it runs last).
struct SandboxGuard
{
  SandboxGuard()
  {
    std::error_code ec;
    fs::remove_all(sandboxRoot(), ec);
    fs::create_directories(sandboxRoot());
  }
  ~SandboxGuard()
  {
    std::error_code ec;
    fs::remove_all(sandboxRoot(), ec);
  }
  fs::path subdir(const std::string &name) const
  {
    fs::path p = sandboxRoot() / name;
    fs::create_directories(p);
    return p;
  }
};

// RAII: install a log-capturing external handler; restore file logging on exit.
struct LogCaptureGuard
{
  std::vector<std::string> messages;
  std::mutex mutex;
  LogCaptureGuard()
  {
    iora::core::Logger::setExternalHandler(
      [this](iora::core::Logger::Level, const std::string &, const std::string &raw)
      {
        std::lock_guard<std::mutex> lock(mutex);
        messages.push_back(raw);
      });
  }
  ~LogCaptureGuard() { iora::core::Logger::clearExternalHandler(); }
  bool sawContaining(const std::string &needle)
  {
    iora::core::Logger::flush();
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto &m : messages)
    {
      if (m.find(needle) != std::string::npos)
      {
        return true;
      }
    }
    return false;
  }
};

std::string readFile(const fs::path &path)
{
  std::ifstream in(path);
  REQUIRE(in.good());
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

void writeFile(const fs::path &path, const std::string &content)
{
  std::ofstream out(path);
  REQUIRE(out.good());
  out << content;
}

void replaceAll(std::string &text, const std::string &from, const std::string &to)
{
  std::size_t pos = 0;
  while ((pos = text.find(from, pos)) != std::string::npos)
  {
    text.replace(pos, from.size(), to);
    pos += to.size();
  }
}

// --- Template variants ------------------------------------------------------

struct TemplateDirs
{
  std::string config;
  std::string log;
  std::string modules;
};

// The real template with exactly the three install tokens filled in. Any other
// @TOKEN@ left over is a misspelled token that configure_file(@ONLY) would blank.
std::string substitutedTemplate(const TemplateDirs &dirs)
{
  std::string text = readFile(IORA_CFG_TEMPLATE_PATH);
  replaceAll(text, "@IORA_CONFIG_DIR@", dirs.config);
  replaceAll(text, "@IORA_LOG_DIR@", dirs.log);
  replaceAll(text, "@IORA_MODULES_DIR@", dirs.modules);
  REQUIRE_FALSE(std::regex_search(text, std::regex("@[A-Za-z_]+@")));
  return text;
}

// The stock file enables nothing marked "#? "; the all-enabled variant strips
// the marker at the start of every line.
std::string enabledVariant(const std::string &stock)
{
  std::istringstream in(stock);
  std::ostringstream out;
  std::string line;
  while (std::getline(in, line))
  {
    if (line.compare(0, 3, "#? ") == 0)
    {
      line.erase(0, 3);
    }
    out << line << '\n';
  }
  return out.str();
}

// --- The key table: every key parseTomlConfig reads ---------------------------

using Config = iora::IoraService::Config;

template <typename T> std::string show(const std::optional<T> &v)
{
  std::ostringstream os;
  os << std::boolalpha << *v;
  return os.str();
}

std::string show(const std::optional<std::chrono::seconds> &v)
{
  return std::to_string(v->count());
}

std::string show(const std::optional<std::vector<std::string>> &v)
{
  std::string joined;
  for (const auto &s : *v)
  {
    joined += (joined.empty() ? "" : ",") + s;
  }
  return joined;
}

struct KeyRow
{
  std::string key;
  bool optionalLine; // "#? "-marked in the template
  std::string expected;
  std::function<bool(const Config &)> isSet;
  std::function<std::string(const Config &)> value;
};

#define IORA_KEY_ROW(KEY, MARKED, EXPECTED, FIELD)                                                 \
  KeyRow                                                                                           \
  {                                                                                                \
    KEY, MARKED, EXPECTED, [](const Config &c) { return c.FIELD.has_value(); },                    \
      [](const Config &c) { return show(c.FIELD); }                                                \
  }

std::vector<KeyRow> keyTable(const TemplateDirs &d)
{
  return {
    IORA_KEY_ROW("iora.server.port", false, "8080", server.port),
    IORA_KEY_ROW("iora.server.tls.certFile", true, d.config + "/tls/server.crt",
                 server.tls.certFile),
    IORA_KEY_ROW("iora.server.tls.keyFile", true, d.config + "/tls/server.key", server.tls.keyFile),
    IORA_KEY_ROW("iora.server.tls.caFile", true, d.config + "/tls/ca.crt", server.tls.caFile),
    IORA_KEY_ROW("iora.server.tls.requireClientCert", true, "false", server.tls.requireClientCert),
    IORA_KEY_ROW("iora.state.file", false, d.config + "/iora_state.json", state.file),
    IORA_KEY_ROW("iora.log.level", false, "debug", log.level),
    IORA_KEY_ROW("iora.log.file", false, d.log + "/iora", log.file),
    IORA_KEY_ROW("iora.log.async", false, "true", log.async),
    IORA_KEY_ROW("iora.log.retentionDays", false, "7", log.retentionDays),
    IORA_KEY_ROW("iora.log.timeFormat", false, "%Y-%m-%d %H:%M:%S", log.timeFormat),
    IORA_KEY_ROW("iora.log.compressAfterDays", false, "0", log.compressAfterDays),
    IORA_KEY_ROW("iora.threadPool.minThreads", false, "2", threadPool.minThreads),
    IORA_KEY_ROW("iora.threadPool.maxThreads", false, "8", threadPool.maxThreads),
    IORA_KEY_ROW("iora.threadPool.queueSize", false, "128", threadPool.queueSize),
    IORA_KEY_ROW("iora.threadPool.idleTimeoutSeconds", false, "60", threadPool.idleTimeoutSeconds),
    IORA_KEY_ROW("iora.modules.directory", false, d.modules, modules.directory),
    IORA_KEY_ROW("iora.modules.autoLoad", true, "true", modules.autoLoad),
    IORA_KEY_ROW("iora.modules.modules", true, "base_module.so,dependent_module.so",
                 modules.modules),
    IORA_KEY_ROW("iora.features.server", true, "true", features.server),
    IORA_KEY_ROW("iora.features.jsonFileStore", true, "true", features.jsonFileStore),
    IORA_KEY_ROW("iora.features.stateStore", true, "true", features.stateStore),
    IORA_KEY_ROW("iora.features.expiringCache", true, "true", features.expiringCache),
    IORA_KEY_ROW("iora.features.modules", true, "true", features.modules),
  };
}

#undef IORA_KEY_ROW

Config parseFile(const fs::path &file)
{
  Config config;
  std::unique_ptr<iora::core::ConfigLoader> loader;
  parseTomlConfig(config, loader, file.string());
  REQUIRE(loader);
  REQUIRE(loader->isLoaded());
  return config;
}

void collectLeafKeys(const iora::parsers::toml::table &table, const std::string &prefix,
                     std::set<std::string> &out)
{
  for (const auto &entry : table)
  {
    const std::string key = prefix.empty() ? entry.first : prefix + "." + entry.first;
    if (const auto *sub = entry.second.as_table())
    {
      collectLeafKeys(*sub, key, out);
    }
    else
    {
      out.insert(key);
    }
  }
}

std::set<std::string> leafKeysOf(const fs::path &file)
{
  iora::core::ConfigLoader loader(file.string());
  REQUIRE(loader.isLoaded());
  std::set<std::string> keys;
  collectLeafKeys(loader.table(), "", keys);
  return keys;
}

std::set<std::string> rowKeys(const std::vector<KeyRow> &rows, bool unmarkedOnly)
{
  std::set<std::string> keys;
  for (const auto &row : rows)
  {
    if (!unmarkedOnly || !row.optionalLine)
    {
      keys.insert(row.key);
    }
  }
  return keys;
}

struct TemplateFixture
{
  SandboxGuard sandbox;
  fs::path cfgDir = sandbox.subdir("cfg");
  TemplateDirs dirs{(cfgDir / "conf").string(), (cfgDir / "log").string(),
                    (cfgDir / "mods").string()};
  std::string stock = substitutedTemplate(dirs);
  std::string enabled = enabledVariant(stock);
  fs::path stockFile = cfgDir / "stock.cfg";
  fs::path enabledFile = cfgDir / "enabled.cfg";
  TemplateFixture()
  {
    writeFile(stockFile, stock);
    writeFile(enabledFile, enabled);
  }
};

// --- Plugin batch helpers ------------------------------------------------------

fs::path builtPlugin(const std::string &name)
{
  fs::path p = fs::path(iora::util::getExecutableDir()) / "plugins" / name;
  REQUIRE(fs::exists(p));
  return p;
}

fs::path stagePlugins(const SandboxGuard &sandbox, const std::string &subdir,
                      const std::vector<std::string> &names)
{
  fs::path dir = sandbox.subdir(subdir);
  for (const auto &name : names)
  {
    fs::copy_file(builtPlugin(name), dir / name);
  }
  return dir;
}

void applySandboxServiceDefaults(Config &cfg, const SandboxGuard &sandbox)
{
  cfg.features.server = false;
  cfg.features.jsonFileStore = false;
  cfg.log.level = "info";
  cfg.log.file = (sandbox.subdir("log") / "svc").string();
}

// A self-referencing symlink: reading its file status fails with ELOOP.
void addSymlinkLoop(const fs::path &dir) { fs::create_symlink("loop.so", dir / "loop.so"); }

Config serviceConfig(const SandboxGuard &sandbox, const fs::path &modulesDir)
{
  Config cfg;
  applySandboxServiceDefaults(cfg, sandbox);
  cfg.modules.directory = modulesDir.string();
  cfg.modules.autoLoad = true;
  return cfg;
}

const std::vector<std::string> kBatch = {"exportthenthrowplugin.so", "dependentplugin.so",
                                         "nonstdonloadthrowplugin.so", "testplugin.so"};

} // namespace

// --- 5.1: every template key lands in its Config field --------------------------

TEST_CASE("iora.cfg.in all-enabled variant: every key lands", "[iora][cli_config]")
{
  TemplateFixture fx;
  Config config = parseFile(fx.enabledFile);
  for (const auto &row : keyTable(fx.dirs))
  {
    INFO("key " << row.key);
    REQUIRE(row.isSet(config));
    REQUIRE(row.value(config) == row.expected);
  }
}

TEST_CASE("iora.cfg.in stock file: parses, optional keys stay unset", "[iora][cli_config]")
{
  TemplateFixture fx;
  Config config = parseFile(fx.stockFile);
  const auto rows = keyTable(fx.dirs);
  REQUIRE(leafKeysOf(fx.stockFile) == rowKeys(rows, true));
  for (const auto &row : rows)
  {
    INFO("key " << row.key);
    if (row.optionalLine)
    {
      REQUIRE_FALSE(row.isSet(config));
    }
    else
    {
      REQUIRE(row.isSet(config));
      REQUIRE(row.value(config) == row.expected);
    }
  }
}

// --- 5.2: template keys == the keys the parser reads ----------------------------

TEST_CASE("iora.cfg.in: template key set equals the parsed key set", "[iora][cli_config]")
{
  TemplateFixture fx;
  REQUIRE(leafKeysOf(fx.enabledFile) == rowKeys(keyTable(fx.dirs), false));
}

// --- 2.3: a bad iora.modules.modules does not drop the keys read after it -------

TEST_CASE("iora.modules.modules with a non-string element: warned, unset, later keys read",
          "[iora][cli_config]")
{
  SandboxGuard sandbox;
  fs::path toml = sandbox.subdir("badlist") / "bad.cfg";
  writeFile(toml, "[iora.modules]\nmodules = [\"a.so\", 1]\n[iora.threadPool]\nminThreads = 5\n");
  LogCaptureGuard logs;
  Config cfg;
  std::unique_ptr<iora::core::ConfigLoader> loader;
  parseTomlConfig(cfg, loader, toml.string());
  REQUIRE(loader);
  REQUIRE(loader->isLoaded());
  REQUIRE_FALSE(cfg.modules.modules.has_value());
  REQUIRE(cfg.threadPool.minThreads == std::size_t{5});
  REQUIRE(logs.sawContaining("Ignoring iora.modules.modules"));
}

// --- 5.5: CLI > TOML precedence --------------------------------------------------

TEST_CASE("parseCliArgs then parseTomlConfig: CLI values win", "[iora][cli_config]")
{
  TemplateFixture fx;
  std::vector<std::string> args = {"iora", "--threadpool-min", "3", "--log-retention", "2"};
  std::vector<char *> argv;
  for (auto &a : args)
  {
    argv.push_back(&a[0]);
  }
  Config config;
  std::unique_ptr<iora::core::ConfigLoader> loader;
  parseCliArgs(static_cast<int>(argv.size()), argv.data(), config, loader);
  parseTomlConfig(config, loader, fx.enabledFile.string());
  REQUIRE(config.threadPool.minThreads == std::size_t{3});
  REQUIRE(config.log.retentionDays == 2);
  REQUIRE(config.threadPool.maxThreads == std::size_t{8});
}

// --- 5.3: a failing module does not stop the batch ------------------------------

TEST_CASE("loadModules configured list: failing modules are skipped", "[iora][cli_config][batch]")
{
  SandboxGuard sandbox;
  fs::path dir = stagePlugins(sandbox, "A", kBatch);
  addSymlinkLoop(dir);
  Config cfg = serviceConfig(sandbox, dir);
  std::vector<std::string> list = {"loop.so"};
  list.insert(list.end(), kBatch.begin(), kBatch.end());
  cfg.modules.modules = list;

  LogCaptureGuard logs;
  REQUIRE_NOTHROW(iora::IoraService::init(cfg));
  auto &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown guard(svc);

  REQUIRE(svc.isModuleLoaded("testplugin.so"));
  REQUIRE_FALSE(svc.isModuleLoaded("exportthenthrowplugin.so"));
  REQUIRE_FALSE(svc.isModuleLoaded("dependentplugin.so"));
  REQUIRE_FALSE(svc.isModuleLoaded("nonstdonloadthrowplugin.so"));

  REQUIRE(logs.sawContaining("Module not found: " + (dir / "loop.so").string() + ": "));
  REQUIRE(logs.sawContaining("loadModules: skipping module " +
                             (dir / "exportthenthrowplugin.so").string() +
                             ": intentional onLoad failure after exportApi"));
  REQUIRE(logs.sawContaining("loadModules: skipping module " +
                             (dir / "dependentplugin.so").string() +
                             ": Required dependency 'baseplugin.so' is not loaded"));
  REQUIRE(logs.sawContaining("loadModules: skipping module " +
                             (dir / "nonstdonloadthrowplugin.so").string() +
                             ": non-standard exception"));

  const auto names = svc.getExportedApiNames();
  REQUIRE(std::find(names.begin(), names.end(), "exportthenthrow.add") == names.end());
  REQUIRE_THROWS_WITH(svc.callExportedApi<int>("exportthenthrow.add", 1, 2),
                      Catch::Contains("API not found"));
  REQUIRE(svc.callExportedApi<int>("testplugin.add", 2, 3) == 5);
  {
    auto f = svc.getExportedApiSafe<int(int, int)>("testplugin.add");
    REQUIRE((*f)(2, 3) == 5);
  }

  REQUIRE_THROWS_WITH(svc.loadSingleModule((dir / "exportthenthrowplugin.so").string()),
                      Catch::Contains("intentional onLoad failure") &&
                        !Catch::Contains("Plugin already loaded"));
}

TEST_CASE("loadModules directory scan: failing modules are skipped", "[iora][cli_config][batch]")
{
  SandboxGuard sandbox;
  fs::path dir = stagePlugins(sandbox, "B", kBatch);
  addSymlinkLoop(dir);
  Config cfg = serviceConfig(sandbox, dir);

  REQUIRE_NOTHROW(iora::IoraService::init(cfg));
  auto &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown guard(svc);

  REQUIRE(svc.isModuleLoaded("testplugin.so"));
  REQUIRE_FALSE(svc.isModuleLoaded("exportthenthrowplugin.so"));
  REQUIRE_FALSE(svc.isModuleLoaded("nonstdonloadthrowplugin.so"));
}

// --- 5.4: the TOML module list is honored, in order ------------------------------

namespace
{
void runOrderScenario(const std::string &subdir, const std::string &first,
                      const std::string &second, bool expectDependentLoaded)
{
  SandboxGuard sandbox;
  fs::path dir = stagePlugins(sandbox, subdir, {"baseplugin.so", "dependentplugin.so"});
  fs::path toml = sandbox.subdir("toml") / "order.cfg";
  writeFile(toml, "[iora.modules]\ndirectory = \"" + dir.string() + "\"\nmodules = [\"" + first +
                    "\", \"" + second + "\"]\n");

  Config cfg;
  std::unique_ptr<iora::core::ConfigLoader> loader;
  parseTomlConfig(cfg, loader, toml.string());
  REQUIRE(cfg.modules.modules.has_value());
  applySandboxServiceDefaults(cfg, sandbox);

  REQUIRE_NOTHROW(iora::IoraService::init(cfg));
  auto &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown guard(svc);
  REQUIRE(svc.isModuleLoaded("baseplugin.so"));
  REQUIRE(svc.isModuleLoaded("dependentplugin.so") == expectDependentLoaded);
}
} // namespace

TEST_CASE("iora.modules.modules from TOML: base before dependent loads both",
          "[iora][cli_config][batch]")
{
  runOrderScenario("order1", "baseplugin.so", "dependentplugin.so", true);
}

TEST_CASE("iora.modules.modules from TOML: dependent before base skips dependent",
          "[iora][cli_config][batch]")
{
  runOrderScenario("order2", "dependentplugin.so", "baseplugin.so", false);
}

// --- 5.6: the require() message names the load-order key ------------------------

TEST_CASE("Plugin::require message names iora.modules.modules", "[iora][cli_config]")
{
  SandboxGuard sandbox;
  fs::path dir = stagePlugins(sandbox, "require", {"dependentplugin.so"});
  Config cfg = serviceConfig(sandbox, dir);
  cfg.modules.autoLoad = false;

  REQUIRE_NOTHROW(iora::IoraService::init(cfg));
  auto &svc = iora::IoraService::instanceRef();
  iora::IoraService::AutoServiceShutdown guard(svc);
  REQUIRE_THROWS_WITH(svc.loadSingleModule((dir / "dependentplugin.so").string()),
                      Catch::Contains("modules.modules"));
}
