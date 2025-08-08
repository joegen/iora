#pragma once

#include <string>
#include <stdexcept>
#include <subprocess.hpp>

namespace iora {
namespace system {
  
  /// \brief Executes shell commands and captures their output as strings.
  class ShellRunner
  {
  public:
    /// \brief Executes a shell command.
    /// \param command The shell command to execute.
    /// \return The output of the command.
    static std::string execute(const std::string& command)
    {
      try
      {
        auto result = subprocess::check_output({"/bin/sh", "-c", command});
        return std::string(result.buf.data(), result.length);
      }
      catch (const std::exception& e)
      {
        throw std::runtime_error("ShellRunner error: " + std::string(e.what()));
      }
    }
  };

} } // namespace iora::system
