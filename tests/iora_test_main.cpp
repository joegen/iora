#define CATCH_CONFIG_MAIN

#include "catch2/catch_test_macros.hpp"
#include "catch2/catch_approx.hpp"
#include "catch2/catch_session.hpp"
#include "catch2/catch_tostring.hpp"
#include "catch2/catch_all.hpp"
#include "iora/iora.hpp"
#include <fstream>
#include <dlfcn.h>

namespace
{

void removeFilesMatchingPrefix(const std::string& prefix)
{
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    if (file.path().string().find(prefix) != std::string::npos)
    {
      std::filesystem::remove(file.path());
    }
  }
}

void removeFilesContainingAny(const std::vector<std::string>& fragments)
{
  for (const auto& file : std::filesystem::directory_iterator("."))
  {
    std::string name = file.path().string();
    for (const auto& fragment : fragments)
    {
      if (name.find(fragment) != std::string::npos)
      {
        std::filesystem::remove(file.path());
        break;
      }
    }
  }
}

std::optional<std::string> findPlugin(const std::string& filename)
{
  std::vector<std::string> paths = {"tests/plugins/", "build/tests/plugins/",
                                    "iora/build/tests/plugins/",
                                    "/workspace/iora/build/tests/plugins/"};

  for (const auto& dir : paths)
  {
    std::string full = dir + filename;
    if (std::filesystem::exists(full))
    {
      return full;
    }
  }
  return std::nullopt;
}

class AutoServiceShutdown
{
public:
  explicit AutoServiceShutdown(iora::IoraService& service) : _svc(service) {}
  ~AutoServiceShutdown() { _svc.shutdown(); }

private:
  iora::IoraService& _svc;
};

} // namespace

#include "iora_test_http.cpp"
#include "iora_test_logger.cpp"
#include "iora_test_event_queue.cpp"
#include "iora_test_iora_service.cpp"
#include "iora_test_config_loader.cpp"
#include "iora_test_plugin.cpp"
#include "iora_test_state.cpp"
