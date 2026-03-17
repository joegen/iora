// iora_core — shared library housing singleton state for cross-plugin unification.

#include "iora/iora.hpp"

namespace iora {
namespace core {

Logger::LoggerData &Logger::getData()
{
  static LoggerData data;
  return data;
}

} // namespace core

// IoraService singleton state — single mutex shared by instancePtr() and destroyInstance()
static std::mutex sInstanceMutex;

std::shared_ptr<IoraService> &IoraService::getInstancePtr()
{
  static std::shared_ptr<IoraService> instance;
  return instance;
}

std::shared_ptr<IoraService> IoraService::instancePtr()
{
  std::lock_guard<std::mutex> lock(sInstanceMutex);
  auto &instance = getInstancePtr();
  if (!instance)
  {
    instance = std::shared_ptr<IoraService>(new IoraService());
  }
  return instance;
}

void IoraService::destroyInstance()
{
  std::lock_guard<std::mutex> lock(sInstanceMutex);
  getInstancePtr().reset();
}

} // namespace iora
