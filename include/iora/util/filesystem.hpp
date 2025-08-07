#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <unistd.h> // for readlink

namespace iora {
namespace util {

  /// \brief Get the path to the currently running executable
  /// \return Full path to the executable as a string
  std::string getExecutablePath()
  {
    std::vector<char> buf(4096);
    ssize_t len = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len > 0)
    {
      buf[len] = '\0';
      return std::string(buf.data());
    }
    return {};
  }

  /// \brief Get the directory of the currently running executable
  std::string getExecutableDir()
  {
    std::string exePath = getExecutablePath();
    if (!exePath.empty())
    {
      return std::filesystem::path(exePath).parent_path().string();
    }
    return {};
  }

  /// \brief Resolve a relative path against an absolute base path
  std::string resolveRelativePath(const std::string& base_absolute_path, const std::string& relative_path)
  {
    // Use std::filesystem to join and normalize the path
    return std::filesystem::weakly_canonical(std::filesystem::path(base_absolute_path) / relative_path).string();
  }

  /// \brief Remove all files in the current directory that match the given
  /// prefix
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

  /// \brief Remove all files in the current directory that contain any of the
  /// given fragments
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

} // namespace util
} // namespace iora
