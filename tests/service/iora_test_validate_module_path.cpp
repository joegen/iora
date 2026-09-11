// Regression tests for IoraService::validateModulePath (tracker 2026-09-10-12).
//
// validateModulePath is a private static member; it is reachable only through
// loadSingleModule(const std::string&), which ALSO returns false for a
// non-existent file, a non-regular file, and an unsupported extension. Every
// test below is therefore constructed to be NON-VACUOUS: the positive cases
// load a REAL, otherwise-loadable copy of testplugin.so, and the "reject"
// case (N1) points a ".."-bearing path at a real, loadable .so so the refusal
// can only come from the traversal guard — not from an exists()/extension
// short-circuit. The mutation expectation for each case is noted inline.
#define CATCH_CONFIG_RUNNER
#include "test_helpers.hpp"
#include <catch2/catch.hpp>
#include <filesystem>
#include <iostream>

using namespace iora::test;

namespace
{
// Copy the built test plugin to a destination path, creating parents as needed.
void copyPluginTo(const std::filesystem::path &source, const std::filesystem::path &dest)
{
  std::filesystem::create_directories(dest.parent_path());
  std::filesystem::copy_file(source, dest, std::filesystem::copy_options::overwrite_existing);
}

// Create a symlink at `link` pointing at `target`, asserting it succeeded.
void makeSymlink(const std::filesystem::path &target, const std::filesystem::path &link)
{
  std::error_code ec;
  std::filesystem::create_symlink(target, link, ec);
  REQUIRE_FALSE(ec);
}
} // namespace

TEST_CASE("validateModulePath: hidden directories accepted, '..' traversal rejected")
{
  iora::IoraService &svc = iora::IoraService::instanceRef();

  const std::filesystem::path exeDir = iora::util::getExecutableDir();
  const std::filesystem::path sourcePlugin = exeDir / "plugins" / "testplugin.so";
  REQUIRE(std::filesystem::exists(sourcePlugin));

  // A unique sandbox root under the (writable) executable directory. Everything
  // this test creates lives under here and is removed on every exit path.
  const std::filesystem::path sandbox = exeDir / "vmp_sandbox";
  std::filesystem::remove_all(sandbox);

  struct CleanupOnExit
  {
    iora::IoraService &svc;
    std::filesystem::path sandbox;
    ~CleanupOnExit()
    {
      // noexcept destructor: swallow so a failed REQUIRE's exception is not
      // masked by std::terminate.
      try
      {
        svc.unloadAllModules();
      }
      catch (...)
      {
      }
      std::error_code ec;
      std::filesystem::remove_all(sandbox, ec);
    }
  } cleanup{svc, sandbox};

  // --- P1: ACCEPT a plugin under a genuinely hidden ('.'-prefixed) directory.
  // This is the core regression: the old "/." substring scan rejected this.
  // Mutation: restoring the "/." substring scan flips this REQUIRE to false.
  {
    const std::filesystem::path hidden = sandbox / ".hidden_dir" / "testplugin.so";
    copyPluginTo(sourcePlugin, hidden);
    REQUIRE(std::filesystem::exists(hidden));
    REQUIRE(svc.loadSingleModule(hidden.string()));
    svc.unloadAllModules();
  }

  // --- P2: ACCEPT a filename that merely CONTAINS ".." as a substring but has
  // no ".." component. Mutation: the old path.find("..") substring scan flips
  // this REQUIRE to false.
  {
    const std::filesystem::path dotsName = sandbox / "dots" / "lib..plugin.so";
    copyPluginTo(sourcePlugin, dotsName);
    REQUIRE(std::filesystem::exists(dotsName));
    REQUIRE(svc.loadSingleModule(dotsName.string()));
    svc.unloadAllModules();
  }

  // --- N1: REJECT a genuine ".." traversal component. The raw input resolves
  // to an EXISTING, loadable .so, so the refusal can only come from the
  // traversal guard (not exists()/extension). Mutation: removing the
  // "..".-component guard flips this to a successful load.
  {
    const std::filesystem::path real = sandbox / "real" / "real.so";
    copyPluginTo(sourcePlugin, real);
    std::filesystem::create_directories(sandbox / "real" / "sub");
    const std::filesystem::path traversal = sandbox / "real" / "sub" / ".." / "real.so";
    // Sanity: the target the "..".resolves to genuinely exists and is loadable.
    REQUIRE(std::filesystem::exists(traversal));
    REQUIRE_FALSE(svc.loadSingleModule(traversal.string()));
    // Guard did its job: nothing was loaded.
    svc.unloadAllModules();
  }

  // --- N2: REJECT a ".." component appearing early in the path. Like N1 the
  // raw input resolves (via "..") to the existing, loadable real.so, so the
  // refusal can only come from the traversal guard — NOT from a nonexistent
  // relative path. Mutation: removing the ".."-component guard flips this to a
  // successful load.
  {
    const std::filesystem::path earlyTraversal =
      sandbox / ".." / sandbox.filename() / "real" / "real.so";
    REQUIRE(std::filesystem::exists(earlyTraversal));
    REQUIRE_FALSE(svc.loadSingleModule(earlyTraversal.string()));
  }

  // --- N3: REJECT an interior ".." component even when the resolved target
  // would exist. Point it back into the sandbox at the real plugin.
  {
    const std::filesystem::path interior =
      sandbox / "real" / "sub" / ".." / ".." / "real" / "real.so";
    REQUIRE(std::filesystem::exists(interior));
    REQUIRE_FALSE(svc.loadSingleModule(interior.string()));
  }

  // --- N4 (symlink hardening): a ".so"-named symlink whose real target is a
  // non-".so" file must be REJECTED. The extension allow-list is applied to the
  // symlink-RESOLVED target, so a genuinely loadable plugin renamed to ".bin"
  // and reached through a ".so" link cannot smuggle itself past the gate.
  // Non-vacuous: the link resolves to an existing, otherwise-loadable file, so
  // only the resolved-extension check produces the refusal. Mutation: reverting
  // to the link-name extension (entry.extension()) flips this to a load.
  {
    const std::filesystem::path target = sandbox / "sym" / "resolved_target.bin";
    copyPluginTo(sourcePlugin, target); // a valid .so payload, non-".so" name
    const std::filesystem::path link = sandbox / "sym" / "plugin.so";
    makeSymlink(target, link);
    REQUIRE(std::filesystem::exists(link));                      // resolves to target
    REQUIRE(std::filesystem::canonical(link).extension() == ".bin"); // real ext
    REQUIRE_FALSE(svc.loadSingleModule(link.string())); // rejected: nothing loaded
  }

  // --- R1 (reload identity): a module loaded through a ".so"-named symlink whose
  // basename differs from its real target must KEEP its link-name identity across
  // reloadModule(). dlopen loads the resolved target, but the plugin's stored
  // _path is the ORIGINAL link, so reload re-runs the funnel on the link and
  // re-derives the same "alias_reload.so" key. Mutation: storing the resolved
  // path in _path makes reload re-register under "real_reload.so", flipping the
  // final isModuleLoaded("alias_reload.so") to false.
  {
    const std::filesystem::path realReload = sandbox / "reload" / "real_reload.so";
    copyPluginTo(sourcePlugin, realReload);
    const std::filesystem::path alias = sandbox / "reload" / "alias_reload.so";
    makeSymlink(realReload, alias);
    REQUIRE(svc.loadSingleModule(alias.string())); // valid .so target, loads
    REQUIRE(svc.isModuleLoaded("alias_reload.so"));
    REQUIRE(svc.reloadModule("alias_reload.so"));
    REQUIRE(svc.isModuleLoaded("alias_reload.so")); // identity preserved
    svc.unloadAllModules();
  }
}

int main(int argc, char *argv[])
{
  Catch::Session session;

  initializeTestLogging();

  iora::IoraService::Config config;
  config.server.port = 8137;
  config.state.file = "ioraservice_vmp_state.json";
  config.log.file = "ioraservice_vmp_log";
  config.modules.autoLoad = false;

  iora::IoraService::init(config);

  int result = session.run(argc, argv);

  iora::IoraService::instanceRef().shutdown();
  iora::util::removeFilesContainingAny({"ioraservice_vmp_log", "ioraservice_vmp_state.json"});

  return result;
}
