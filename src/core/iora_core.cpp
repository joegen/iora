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
} // namespace iora
