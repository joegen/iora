// iora_core — shared library housing singleton state for cross-plugin unification.

#include "iora/iora.hpp"
#include "iora/core/metrics.hpp"

namespace iora {
namespace core {

// MetricBase vtable anchor
MetricBase::~MetricBase() = default;

// MetricsRegistry singleton — function-local static, available before IoraService::init()
MetricsRegistry& MetricsRegistry::instance()
{
  static MetricsRegistry registry;
  return registry;
}

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

namespace storage {

std::set<JsonFileStore *> &JsonFileStore::registry()
{
  static std::set<JsonFileStore *> s;
  return s;
}

std::mutex &JsonFileStore::registryMutex()
{
  static std::mutex m;
  return m;
}

std::thread &JsonFileStore::flushThread()
{
  static std::thread t;
  return t;
}

std::chrono::milliseconds &JsonFileStore::flushInterval()
{
  static std::chrono::milliseconds ms{2000};
  return ms;
}

std::condition_variable &JsonFileStore::terminationCv()
{
  static std::condition_variable cv;
  return cv;
}

std::mutex &JsonFileStore::terminateCvMutex()
{
  static std::mutex m;
  return m;
}

std::atomic<bool> &JsonFileStore::shouldExit()
{
  static std::atomic<bool> flag{false};
  return flag;
}

} // namespace storage

} // namespace iora
