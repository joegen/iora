#pragma once
//
// FdCloser — move-only RAII file-descriptor closer for the transport engines
// (tracker 2026-09-15-3).
//
// Collect fds during teardown, then ::close them AFTER the owning session/listener
// has been removed from its map under the write lock, so a cross-thread getter
// (holding the shared lock) can never syscall on a closed/reused fd. Structural
// leak-safety: the fd is ::close()d on destruction. It previously existed as a
// byte-for-byte-identical private struct in BOTH detail/tcp_engine.hpp and
// detail/udp_engine.hpp; lifting it here retires the duplicate (the same CF-L1
// de-duplication already applied to addressFromSockaddr / applyDscpToFd).
//
// \p preClose (optional, TEST-ONLY) points at the engine's _preCloseHook; when
// non-empty it is invoked with the fd immediately before ::close (the deterministic
// fd-reuse test dup2()s a sentinel there). Bound to the ::close -- not a separate
// loop -- so a re-ordering regression carries the seam with it. nullptr/empty in
// production. The hook MUST NOT throw: closeIfOpen() runs in the (noexcept)
// destructor, so a throwing hook would std::terminate.

#include <functional>
#include <unistd.h>

namespace iora
{
namespace network
{
namespace detail
{

struct FdCloser
{
  int fd{-1};
  const std::function<void(int)> *preClose{nullptr};
  FdCloser() = default;
  explicit FdCloser(int f, const std::function<void(int)> *hook = nullptr)
    : fd(f), preClose(hook)
  {
  }
  FdCloser(FdCloser &&o) noexcept : fd(o.fd), preClose(o.preClose)
  {
    o.fd = -1;
  }
  FdCloser &operator=(FdCloser &&o) noexcept
  {
    if (this != &o)
    {
      closeIfOpen();
      fd = o.fd;
      preClose = o.preClose;
      o.fd = -1;
    }
    return *this;
  }
  FdCloser(const FdCloser &) = delete;
  FdCloser &operator=(const FdCloser &) = delete;
  ~FdCloser()
  {
    closeIfOpen();
  }

private:
  void closeIfOpen()
  {
    if (fd >= 0)
    {
      if (preClose && *preClose)
      {
        (*preClose)(fd); // TEST-ONLY seam; contract: must not throw (noexcept dtor).
      }
      ::close(fd);
    }
  }
};

} // namespace detail
} // namespace network
} // namespace iora
