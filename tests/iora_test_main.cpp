#define CATCH_CONFIG_MAIN

#include <catch2/catch.hpp>
#include "iora/iora.hpp"

// Initialize debug logging for transport debugging
namespace
{
struct LoggerInit
{
  LoggerInit()
  {
    iora::core::Logger::setLevel(iora::core::Logger::Level::Debug);
  }
};
static LoggerInit init;
} // namespace
#include <fstream>
#include <dlfcn.h>

namespace
{
using AutoServiceShutdown = iora::IoraService::AutoServiceShutdown;
} // namespace

// Helper function to create IoraService from CLI-style arguments
inline iora::IoraService& initServiceFromArgs(int argc, const char* args[])
{
  return iora::IoraService::init(argc, const_cast<char**>(args));
}

#include "iora_test_http.cpp"
#include "iora_test_webhook_transport.cpp"
#include "iora_test_logger.cpp"
#include "iora_test_event_queue.cpp"
#include "iora_test_iora_service.cpp"
#include "iora_test_config_loader.cpp"
#include "iora_test_plugin.cpp"
#include "iora_test_state.cpp"
#include "iora_test_threadpool.cpp"
#include "iora_test_expiring_cache.cpp"
#include "iora_test_shared_udp.cpp"
#include "iora_test_shared_tcp.cpp"
#include "iora_test_unified_tcp_udp.cpp"
#include "iora_test_transport_improvements.cpp"
#include "iora_test_batch_processor.cpp"
#include "iora_test_batch_integration.cpp"
#include "iora_test_dns_client.cpp"
#include "iora_test_timer.cpp"
