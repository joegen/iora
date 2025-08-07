#define CATCH_CONFIG_MAIN

#include "catch2/catch_test_macros.hpp"
#include "catch2/catch_approx.hpp"
#include "catch2/catch_session.hpp"
#include "catch2/catch_tostring.hpp"
#include "catch2/catch_all.hpp"
#include "iora/iora.hpp"
#include <fstream>
#include <dlfcn.h>

namespace { using AutoServiceShutdown = iora::IoraService::AutoServiceShutdown; } // namespace

#include "iora_test_http.cpp"
#include "iora_test_logger.cpp"
#include "iora_test_event_queue.cpp"
#include "iora_test_iora_service.cpp"
#include "iora_test_config_loader.cpp"
#include "iora_test_plugin.cpp"
#include "iora_test_state.cpp"
#include "iora_test_threadpool.cpp"
#include "iora_test_expiring_cache.cpp"
