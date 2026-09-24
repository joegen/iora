# Iora ShellRunner -- Architecture & Programmer's Guide

[Back to index](../../README.md)

| | |
|---|---|
| **Version** | 1.0 |
| **Date** | 2026-09-24 |
| **Status** | IMPLEMENTED |
| **Header** | `include/iora/system/shell_runner.hpp` |
| **Namespace** | `iora::system` |
| **Platform** | Linux only (`/proc` is read by `findProcesses`, `killProcesses`, `waitForCommandReady`; `/bin/sh` is exec'd) |
| **Dependencies** | POSIX (`fork`, `execve`/`execl`, `waitpid`, `kill`, `setsid`, `setpgid`, `getpgid`, `popen`/`pclose`, `fcntl`, `opendir`); C++17 standard library (`<cctype>`, `<chrono>`, `<mutex>`, `<optional>`, `<regex>`, `<thread>`, `<fstream>`, ...). No `iora/core` dependency. |

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-09-24 | Initial guide, authored against source; it is the new home of the README "Process Lifecycle Management - ShellRunner" section, which the README index-transform step (DOC-4) removes. Documents the `PcloseDeleter` / `pcloseExitCode` exit-code handling (iora `45cdb88`) and fixes made with this guide: the destructor now signals the process group only when the child leads its own group (it previously SIGKILLed the **caller's** group when `createProcessGroup` was false), `wait()` re-checks the cached result on every locked iteration (a concurrent reap by another thread no longer overwrites a valid exit status with `Unknown`), the kill step is shared by both termination strategies (`killForCleanup()`), `terminate()` now delegates to `kill()`; `killProcessGroup()` refuses group 1 (`kill(-1)` is a broadcast); a redirect is kept when `open()` reuses the target fd (the caller had fd 1/2 closed); and the header comments for `ProcessHandle`, `TerminationStrategy::Graceful`, `terminate()`, `killProcessGroup`, `closeStdin`, `waitUntilReady()`, `waitForCommandReady()`, `killForCleanup()` and the child's `setsid()` now describe what the code does. The remaining behavioral defects are tracked in coding_trackers `tasks/iora/backlog/2026-09-24-4_shell-runner-behavioral-hardening_P0.json` and listed in Known Limitations. |

---

## 1. Executive Summary

### Problem

Tests and tools need to run shell commands and manage background processes: start a SIP test agent or a helper server, wait for it, and make sure it is gone when the test ends -- even if the test throws. Hand-rolled `system()` / `popen()` plus `pkill` cleanup leaks orphaned processes, loses exit codes, and races on PIDs.

### Solution

`shell_runner.hpp` provides three layers:

- **Synchronous execution** (`ShellRunner::execute`, `executeWithOptions`, `executeWithInput`) -- run a command through `popen("r")` and collect its stdout and exit code (`shell_runner.hpp:810-943`).
- **Background processes** (`ShellRunner::spawn` returning a move-only RAII `ProcessHandle`) -- `fork()` + `/bin/sh -c`, an optional new session/process group, stdout/stderr redirection, and automatic termination of the process (or its whole process group) when the handle is destroyed (`:112-763`, `:953-978`).
- **PID helpers** (`findProcesses`, `killProcesses`, `isProcessRunning`, `getProcessState`, `waitForProcess`, `sendSignal`, `killProcessGroup`) -- `/proc` scanning and thin `kill`/`waitpid` wrappers (`:983-1204`).

### Technical impact

Header-only and dependency-free apart from POSIX. When the process is still running at scope exit and the strategy is not `None`, the RAII handle sends `SIGKILL` and makes a bounded reap attempt, so a test that fails mid-way does not leave its helper running. The design is aimed at **test and tooling code**: there is no stdin pipe to a background process (the synchronous `executeWithInput` can feed stdin), no separate stderr capture, and termination is always `SIGKILL` (see §9 and §10). Every command goes through `/bin/sh -c`, so command strings are shell-interpreted -- never pass untrusted input.

---

## 2. System Architecture

```
                      ShellRunner (static)
     +-------------------------+----------------------------+
     | synchronous             | background                 | PID helpers
     | execute(cmd)            | spawn(cmd, SpawnOptions)   | findProcesses / killProcesses   (/proc)
     | execute(cmd, ostream)   |   fork()                   | isProcessRunning / getProcessState
     | executeWithOptions(...) |   child: setsid, dup2,     | waitForProcess  (waitpid WNOHANG)
     | executeWithInput(...)   |          chdir, exec sh -c | sendSignal / killProcessGroup (kill)
     |   popen("r") + fgets    |   parent: setpgid          |
     |   pclose -> exit code   |   -> ProcessHandle         |
     +-------------------------+-------------+--------------+
                                             |
                                    ProcessHandle (RAII, move-only)
                                    _pid, strategy, killProcessGroup, _detached,
                                    _command, _cachedWaitResult, _mutex
                                    ~ProcessHandle -> cleanupProcess(): SIGKILL (group if killProcessGroup and leader, else PID), reap
```

Consumers are Iora's own test suite and downstream integration fixtures; nothing in the iora library itself calls `ShellRunner`.

---

## 3. Component Deep Dive

### 3.1 Synchronous execution

| Function | Behavior | Source |
|---|---|---|
| `execute(cmd)` | `popen(cmd, "r")`, append stdout in 128-byte `fgets` chunks, `pclose` -> `pcloseExitCode`; throws `std::runtime_error` if `popen` fails **or the exit code is non-zero** (the captured output is discarded; the message carries only the exit code); returns stdout | `:810-836` |
| `execute(cmd, std::ostream &)` | same, but writes and flushes each chunk to the stream as it arrives; **returns** the exit code instead of throwing on non-zero (throws only if `popen` fails) | `:842-860` |
| `executeWithOptions(cmd, opts)` | builds `K=V ... cd DIR && cmd` (`buildCommand`, `:1207-1226`), `popen`; with `timeout > 0` reads non-blocking (`readWithTimeout`, `:1228-1269`), else reads to EOF; fills `ExecutionResult{exitCode, stdout, timedOut, duration}`; with `throwOnError` (default `true`) throws on `popen` failure or a non-zero exit that did not time out; without it, a `popen` failure returns `exitCode = -1` | `:866-914` |
| `executeWithInput(cmd, input)` | writes `input` to `/tmp/iora_shell_input_<pid>`, runs `execute(cmd + " < " + file)`, unlinks the file; same throw rules as `execute(cmd)`. The shell binds `< file` to the **last** simple command only, so for `a; b` or `a && b` only `b` reads the input (use `( a; b )`) | `:920-943` |

**Exit codes.** `pcloseExitCode` (`:786-801`) converts `pclose()`'s wait status: `-1` if `pclose` failed, `WEXITSTATUS` for a normal exit, `128 + signal` for a signal-terminated command (shell convention -- indistinguishable from a command that really exits with that code), and the raw status otherwise. `PcloseDeleter` (`:770-779`) is a stateless functor used as the `std::unique_ptr` deleter so the pipe is closed if reading throws; each function `release()`s the pointer and calls `pclose` itself when it wants the status. (A functor rather than `decltype(&pclose)` avoids GCC 14's `-Wignored-attributes` error under `-Werror`.) Both are implementation helpers that happen to be public in `iora::system`.

**Output handling.** Output is read with `fgets` and appended as a C string, so a `NUL` byte in the command's output truncates that chunk. Only stdout is captured; stderr goes to the caller's stderr unless the command redirects it (`2>&1`).

**Options that do nothing today.** `ExecutionOptions::input` and `ExecutionOptions::captureStderr` are never read, and `ExecutionResult::stderr` is never filled in. Use `executeWithInput` for stdin and `2>&1` in the command for stderr.

**Environment and working directory.** `buildCommand` prepends `K=V ` for each entry and `cd DIR && ` before the command, without quoting. Because of shell parsing, the assignments apply to the **first simple command only** -- and when `workingDirectory` is set that command is `cd`, so the variables do **not** reach your command at all. Even without a working directory they are not visible to the command's own `$VAR` expansions (`echo $FOO` prints nothing): they are only in that command's environment. See §10.

**Timeout.** With `timeout > 0` the pipe is switched to `O_NONBLOCK` and polled every 1 ms until EOF or the deadline; on the deadline `timedOut = true` and reading stops. The child is **not** signalled, and the following `pclose()` waits for it to exit, so `executeWithOptions` returns only when the command finishes by itself. The timeout bounds reading, not the command. Because `pclose()` closes the read end first, a command that writes again after the deadline gets `SIGPIPE`, so, when `SIGPIPE` is not ignored in the caller (a default or caught disposition both become the default action in the child after `exec`), a timed-out result often carries `exitCode == 141` (`128 + SIGPIPE`) alongside `timedOut == true`; with `SIGPIPE` ignored in the caller (inherited by the child) the command sees `EPIPE` and exits with its own code.

### 3.2 `spawn` and the child

`spawn(cmd, SpawnOptions)` (`:953-978`) calls `fork()` (throwing `std::runtime_error` on failure). The child runs `childProcessSetup` (`:1272-1388`), which never returns:

1. If `createProcessGroup` (default `true`): reset `SIGTERM`/`SIGINT`/`SIGHUP` to `SIG_DFL`, then `setsid()`; if that fails, `setpgid(0, 0)`.
2. If `stdoutFile` / `stderrFile` is set: `open(O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644)` and `dup2` onto fd 1 / fd 2 (if the caller had that fd closed, `open()` reuses it and it is kept, with `O_CLOEXEC` cleared); `_exit(127)` on failure. Because this happens before step 3, a relative path resolves against the **caller's** working directory, not `workingDirectory` (SR-25); and the same path for both opens the file twice with independent offsets, so the streams overwrite each other -- use `2>&1` in the command with `stdoutFile` only (SR-24).
3. If `workingDirectory` is set: `chdir`, `_exit(127)` on failure.
4. Exec `/bin/sh -c cmd`: with `execve` and **only** the given variables when `environment` is non-empty (the inherited environment, including `PATH`, is replaced), else with `execl` inheriting the parent's environment. `_exit(127)` if exec fails.

The parent also calls `setpgid(pid, pid)` when `createProcessGroup` is set, ignoring errors, then returns `ProcessHandle(pid, terminationStrategy, killProcessGroup, cmd)`.

**Expect the child to stay in the caller's session.** The parent's `setpgid(pid, pid)` and the child's `setsid()` race, and the parent practically always wins (measured: 0 new sessions in 200 spawns on Linux with dash). The child is then already a group leader, `setsid()` fails, and the fallback `setpgid(0, 0)` changes nothing: it has its own process group but keeps the caller's controlling terminal, so if the test runs from a terminal and the command reads stdin, it is stopped by `SIGTTIN` -- redirect stdin (`< /dev/null`) for anything that might read it. Either way it leads its own process group, which is what group termination relies on. (`createProcessGroup` therefore means "new process group"; a new session is not something to rely on, SR-14.)

**The PID is the `sh` wrapper, not your command.** `/bin/sh -c cmd` runs `cmd` as a child; dash (Debian/Ubuntu `/bin/sh`) does this even for a simple command. So `pid()`, `terminate()`, `kill()` and `signal()` all refer to `sh`: signalling it leaves the real command running, and once `sh` has exited (whether or not you queried the handle) the destructor no longer signals the group (SR-19), so the command is orphaned. Prefix the command with `exec` (`spawn("exec my-server --port 8080")`) when you want the PID to be the command itself -- this works for a single simple command only (`exec a && b` never runs `b`, `exec a | b` does not make the PID `a`; use `workingDirectory` rather than `exec cd dir && srv`) -- or signal the whole group with `ShellRunner::killProcessGroup(pid(), sig)`. (With `exec`, `waitForCommandReady()` no longer matches, SR-16.) `SpawnOptions::closeStdin` is never read: the child always inherits the parent's stdin.

### 3.3 `ProcessHandle`

| Member | Behavior | Source |
|---|---|---|
| `pid()` | the managed PID, `-1` after being moved from | `:212-215` |
| `isRunning()` | after an unlocked `_pid <= 0` check, under `_mutex`: the cached result if any, else `waitpid(WNOHANG)`; an exited child is **reaped** and its status cached | `:218-254` |
| `getState()` | same, returning `Running` / `Exited` / `Signaled` / `Unknown` | `:257-289` |
| `wait(timeout)` | `timeout <= 0` waits forever; polls `waitpid(WNOHANG)` every 10 ms (lock held only around each `waitpid`, and the cache re-checked under the lock each time); returns the cached `WaitResult` if already reaped, including by another thread mid-wait; on timeout returns `{timedOut = true, state = Running}` (not cached); a `waitpid` error caches and returns `state = Unknown` | `:294-354` |
| `terminate()` | same as `kill()`: `kill(pid, SIGKILL)` to the **PID only**, i.e. the `sh` wrapper unless the command was `exec`'d (ignores `killProcessGroup`); `false` if the PID no longer exists (an exited but unreaped zombie still exists, so it returns `true` for it) | `:364-367` |
| `kill()` | same as `terminate()` | `:370-379` |
| `signal(sig)` | `kill(pid, sig)` to the PID only | `:382-389` |
| `detach()` | marks the handle detached under `_mutex`; the destructor then leaves the process alone | `:392-397` |
| `waitUntilReady(timeout)` | polls `kill(pid, 0)` every 10 ms; true as soon as the PID exists -- normally immediately after `spawn`, and also for an exited-but-unreaped (zombie) child, so it does not prove the exec succeeded | `:408-440` |
| `waitForCommandReady(timeout)` | scans `/proc/*/cmdline` every 10 ms for any process whose command line contains both `"sh"` and the spawned command string | `:450-518` |
| `setTerminationStrategy(s)` | changes the destructor strategy under `_mutex` | `:521-525` |
| `waitpidWithEINTR(pid, status, opts)` | `waitpid`, retried on `EINTR` (public static helper) | `:532-544` |

**A stopped child counts as running.** No `waitpid` here uses `WUNTRACED`, so a child stopped by `SIGTTIN` / `SIGSTOP` reports `Running` from `isRunning()` / `getState()`, and `wait()` without a timeout blocks until it is continued (SR-22).

**`WaitResult` fields.** `state` is the reliable field: `Exited` (use `exitCode`), `Signaled` (use `signal`), `Running` (with `timedOut`), or `Unknown`. `exited` is set to `true` whenever the child was reaped, **including** when a signal killed it (then `exitCode` stays `0`), despite its comment saying "True if process exited". Do not test `exited && exitCode == 0` for success; test `state == State::Exited && exitCode == 0`.

**Destruction (`cleanupProcess`, `:586-738`).** Runs under `_mutex` (released during each 10 ms sleep). Nothing happens if the handle is detached, moved-from, or the strategy is `None`. Otherwise, if `waitpid(WNOHANG)` says the process is still running:

- `Graceful` (default): send `SIGKILL` through `killForCleanup()` -- to the process group (`-pgid`) when `killProcessGroup` is set **and** the process leads its own group (`getpgid(pid) == pid`), otherwise to the PID -- then poll up to **5 s** to reap; if still not reaped, send `SIGKILL` to the PID again and poll up to **1 s** more, then give up (a zombie may remain).
- `Immediate`: the same `SIGKILL`, then poll up to **1 s**.

The group-leader check means a child spawned with `createProcessGroup = false` (which shares the caller's process group) is killed by PID only. Despite its name, `Graceful` never sends `SIGTERM`; the difference from `Immediate` is only the longer reap wait. If the process had already exited, its status is reaped and cached and **no signal is sent**, so anything the leader left running in its group (a background job such as `sh -c "server &"`, or a daemonizing child) survives; the same holds if `wait()` / `isRunning()` / `getState()` reaped the leader earlier (SR-19). One exception makes this worse, not better: if the handle already reaped its child and the kernel has since reused that PID for **another child of this process** (for example a later `spawn()`), the destructor treats that child as its own, `SIGKILL`s it (its whole group, if it leads one) and steals its exit status (SR-11). The destructor is `noexcept`.

**Move semantics.** Move construction transfers everything and leaves the source with `pid = -1`, detached. Move assignment first runs `cleanupProcess()` on the target's current process (so assigning over a live handle kills it), then transfers under the target's `_mutex`.

### 3.4 PID helpers

| Function | Behavior | Source |
|---|---|---|
| `findProcesses(pattern)` | `std::regex_search` of `pattern` against every `/proc/<pid>/cmdline` (arguments joined with spaces); returns matching PIDs. May match the calling process. Throws `std::regex_error` for an invalid pattern | `:983-1036` |
| `killProcesses(pattern, sig = SIGKILL, waitFor = 200ms)` | `kill` each `findProcesses` match -- which may include the calling process -- sleep `waitFor`, return the number successfully signalled | `:1043-1063` |
| `isProcessRunning(pid)` | `waitpid(pid, WNOHANG) == 0` -- **only meaningful for a child of this process**, and it reaps an exited child | `:1068-1078` |
| `getProcessState(pid)` | same `waitpid`, mapped to `State`; `Unknown` for a non-child | `:1083-1110` |
| `waitForProcess(pid, timeout)` | the `ProcessHandle::wait` loop for a raw PID (children only) | `:1116-1176` |
| `sendSignal(pid, sig)` | `kill(pid, sig) == 0` | `:1182-1189` |
| `killProcessGroup(pgid, sig = SIGKILL)` | `kill(-pgid, sig) == 0`; refuses `pgid <= 1`, since `kill(-1, sig)` is a broadcast to every process the caller may signal, not "group 1" (not related to the `SpawnOptions::killProcessGroup` flag of the same name) | `:1197-1204` |

Because the three `waitpid`-based helpers reap, calling them on a PID owned by a `ProcessHandle` steals its exit status: the handle's later `wait()` sees `ECHILD` and reports `State::Unknown`. Query a handle through the handle.

---

## 4. Usage Guide

**Safe defaults for background processes.**
- The PID is the `sh -c` wrapper (with dash; bash may exec a simple command). Use `exec cmd ...` -- for a single simple command only -- when you need the PID to be the command. Stop helpers by signalling the **group** before the leader is reaped (example 9), or by destroying the handle while the helper is still running; `terminate()` / `kill()` alone are enough only for an `exec`'d command that does not fork.
- Redirect stdin (`< /dev/null`, or the program's own no-stdin flag) for anything that might read it; the child keeps your terminal.
- Once the leader has **exited**, group cleanup is gone: whoever reaps it -- a query (`wait()`, `isRunning()`, `getState()`) or the destructor's own `waitpid` -- sends nothing to the group, and there is then no race-free way to target the group by ID. Sweep the group *before* the leader is reaped (example 9); never call example 9 on a handle that has already reported the exit.

**1. Run a command and capture its output.** The returned string keeps the command's trailing newline.

```cpp
#include <iora/system/shell_runner.hpp>

#include <string>

std::string kernelRelease()
{
  // Throws std::runtime_error if the command exits non-zero.
  return iora::system::ShellRunner::execute("uname -r");
}
```

**2. Stream output and inspect the exit code without throwing.**

```cpp
#include <iora/system/shell_runner.hpp>

#include <iostream>

int runBuildStep()
{
  return iora::system::ShellRunner::execute("make -C build 2>&1", std::cout);
}
```

**3. Options: working directory and a non-throwing result.**

```cpp
#include <iora/system/shell_runner.hpp>

#include <string>

bool listDir(const std::string &dir, std::string &out)
{
  iora::system::ExecutionOptions opts;
  opts.workingDirectory = dir; // not quoted: must not contain spaces or shell metacharacters
  opts.throwOnError = false;
  auto r = iora::system::ShellRunner::executeWithOptions("ls -1", opts);
  out = r.stdout;
  return r.exitCode == 0;
}
```

To pass environment variables to a command, put them in the command string (`"export K=V && cmd"`) rather than in `ExecutionOptions::environment`, which does not reach the command when `workingDirectory` is set (§3.1).

**4. Feed stdin.**

```cpp
#include <iora/system/shell_runner.hpp>

#include <string>

std::string sortLines(const std::string &text)
{
  return iora::system::ShellRunner::executeWithInput("sort", text);
}
```

**5. A background helper that is always cleaned up.**

```cpp
#include <iora/system/shell_runner.hpp>

#include <chrono>

void withHelperServer()
{
  using namespace iora::system;

  SpawnOptions opts;
  opts.stdoutFile = "/tmp/helper.out";
  opts.stderrFile = "/tmp/helper.err";

  ProcessHandle helper = ShellRunner::spawn("exec python3 -m http.server 18080 --bind 127.0.0.1 < /dev/null", opts);

  // ... wait for the port to accept connections, then exercise the helper; if this throws, ~ProcessHandle SIGKILLs the
  // helper's process group (while the helper itself is still alive) and reaps it.

  auto r = helper.wait(std::chrono::milliseconds(100));
  if (r.timedOut)
  {
    // Still running: the destructor will kill it on scope exit.
  }
}
```

**6. Wait for a process to finish, with a deadline.**

```cpp
#include <iora/system/shell_runner.hpp>

#include <chrono>

int runWithDeadline()
{
  using namespace iora::system;
  ProcessHandle p = ShellRunner::spawn("sleep 1; exit 3");
  auto r = p.wait(std::chrono::seconds(5));
  switch (r.state)
  {
  case ProcessHandle::State::Exited:
    return r.exitCode;
  case ProcessHandle::State::Signaled:
    return 128 + r.signal;
  case ProcessHandle::State::Running:
    return -1; // timed out; the destructor kills it
  default:
    return -2; // Unknown: waitpid failed (e.g. the child was reaped elsewhere)
  }
}
```

**7. Let a process outlive the handle.**

```cpp
#include <iora/system/shell_runner.hpp>

#include <sys/types.h>

pid_t startDaemon()
{
  using namespace iora::system;
  ProcessHandle p = ShellRunner::spawn("exec my-daemon --foreground < /dev/null > /tmp/my-daemon.log 2>&1");
  p.detach(); // destructor will not signal it; the caller now owns reaping
  // exec makes the returned PID the daemon itself rather than the sh wrapper; the
  // redirections stop it holding the caller's stdin/stdout/stderr (a detached child that
  // keeps a captured stdout open makes `./app | cat` or a CI log capture wait for it)
  return p.pid();
}
```

**8. A test fixture that owns its helper process.** Holding the handle as a fixture member replaces "start with `-bg`, then `pkill -f` by pattern" cleanup: the helper's process group (provided the helper is still running) is killed when the fixture is destroyed, even if the test throws, and no unrelated process matching a `pkill` pattern is touched. `-nostdin` keeps `sipp` off the terminal it would otherwise share (see §3.2).

```cpp
#include <iora/system/shell_runner.hpp>

#include <optional>
#include <string>

class UasFixture
{
public:
  void startUas(const std::string &scenario, int port)
  {
    iora::system::SpawnOptions opts;
    opts.stdoutFile = "/tmp/uas.out";
    opts.stderrFile = "/tmp/uas.err";
    _uas.emplace(iora::system::ShellRunner::spawn(
      "exec sipp -nostdin -sf " + scenario + " -i 127.0.0.1 -p " + std::to_string(port), opts));
    // Readiness is the caller's job: poll the port or a log line here;
    // waitUntilReady()/waitForCommandReady() do not prove the helper is listening.
  }

  bool uasFinished()
  {
    return _uas && !_uas->isRunning();
  }

private:
  std::optional<iora::system::ProcessHandle> _uas; // destroyed with the fixture
};
```

**9. Shut a helper down cleanly, then sweep its group.** `SIGTERM` (and `SIGCONT`, in case a member is stopped) the whole group, wait for the leader to exit **without reaping it**, give the other members a grace period, `SIGKILL` whatever is left, and only then reap. An exited but unreaped leader is a zombie that keeps its group ID reserved, so every signal to `-pgid` below reaches this group and no other; reaping first would free the ID for reuse. `waitid(..., WNOWAIT)` observes the exit without reaping -- the handle does not offer that, so the recipe calls it directly (the PID is the caller's own child). The zombie is itself still a group member, so `kill(-pgid, 0)` cannot tell whether other members remain; the recipe therefore sends the final `SIGKILL` unconditionally (harmless to the zombie and to an empty remainder). Preconditions: `createProcessGroup` (the default), and the handle has **not** already reported the exit (after a reap no safe sweep exists; SR-19). It blocks for up to about twice `grace`.

```cpp
#include <iora/system/shell_runner.hpp>

#include <chrono>
#include <csignal>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

// Returns false (and does nothing) if the handle's PID is not a live group leader.
bool stopHelper(iora::system::ProcessHandle &helper,
                std::chrono::milliseconds grace = std::chrono::seconds(5))
{
  using namespace iora::system;
  using Clock = std::chrono::steady_clock;
  const pid_t pgid = helper.pid();
  if (pgid <= 1 || getpgid(pgid) != pgid)
  {
    return false; // not a group leader (createProcessGroup = false), or no longer exists
  }
  ShellRunner::killProcessGroup(pgid, SIGTERM);
  ShellRunner::killProcessGroup(pgid, SIGCONT); // a stopped member cannot act on SIGTERM

  // 1. Wait for the leader to exit, leaving its zombie in place so pgid stays reserved.
  const auto leaderDeadline = Clock::now() + grace;
  siginfo_t info{};
  while (Clock::now() < leaderDeadline)
  {
    info.si_pid = 0;
    if (::waitid(P_PID, static_cast<id_t>(pgid), &info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
        info.si_pid == pgid)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  // 2. Let the other members finish, then kill whatever is left. Safe: the
  //    unreaped leader still reserves pgid.
  std::this_thread::sleep_for(grace);
  ShellRunner::killProcessGroup(pgid, SIGKILL);

  // 3. Only now reap the leader.
  helper.wait(std::chrono::seconds(1));
  return true;
}
```

Afterwards, destroy or reset the handle rather than keeping it: it has reaped its child, and a long-lived reaped handle is exposed to SR-11(b). The one remaining assumption is that nothing else (another thread, a `SIGCHLD` handler, `SIGCHLD = SIG_IGN`) reaps the leader in the meantime.

**Anti-patterns.**
- Do NOT pass untrusted input in a command, `workingDirectory`, or environment value -- everything is interpreted by `/bin/sh` and nothing is quoted.
- Do NOT rely on `ExecutionOptions::timeout` to stop a hung command; it stops reading, then waits for the command to exit on its own.
- Do NOT call `ShellRunner::isProcessRunning` / `getProcessState` / `waitForProcess` on a PID a `ProcessHandle` owns; they reap the child and the handle loses its exit status.
- Do NOT expect `Graceful` termination or `terminate()` to deliver `SIGTERM`; both send `SIGKILL`, so the process's cleanup handlers never run. If a process must shut down cleanly, send `SIGTERM` to its **group** yourself -- `ShellRunner::killProcessGroup(p.pid(), SIGTERM)` (valid while the leader is unreaped, because with `createProcessGroup` the PID is the group ID), as in Usage example 9. `p.signal(SIGTERM)` reaches only the `sh -c` wrapper, which is not your command unless it was `exec`'d.
- Do NOT signal a handle after it has reported the child as exited: `terminate()` / `kill()` / `signal()` do not check the cached result, and the PID may have been reused.
- Do NOT use `waitUntilReady()` or `waitForCommandReady()` as a readiness check. `waitUntilReady()` only proves the PID exists (a zombie qualifies); `waitForCommandReady()` matches the `sh -c` wrapper itself, and can also miss the command once `sh` execs it. Poll for the real readiness signal (a port, a file, a log line).
- Do NOT test `WaitResult::exited` for success; it is also `true` for a signal-killed process. Test `state`.
- Do NOT call `killProcesses` with a pattern that can match your own command line; the default signal is `SIGKILL`.
- Do NOT set `SpawnOptions::environment` expecting it to add to the inherited environment; it replaces it, including `PATH`.
- Do NOT call `executeWithInput` concurrently from two threads of one process; they share the same temporary file name.

---

## 5. Call Flow / Sequence Reference

**`executeWithOptions(cmd, opts)`** -> `buildCommand` -> `popen(full, "r")` (fail: throw, or `exitCode = -1`) -> `timeout > 0` ? `readWithTimeout` (non-blocking `fgets`, 1 ms sleeps, stop at EOF or deadline) : `fgets` to EOF -> `pclose` (blocks until the child exits) -> `pcloseExitCode` -> `duration` -> throw if `throwOnError && exitCode != 0 && !timedOut`.

**`spawn(cmd, opts)`** -> `fork()` -> child: [`setsid`, else `setpgid(0,0)`] -> [redirect fd 1/2] -> [`chdir`] -> `exec /bin/sh -c cmd` (or `_exit(127)`) ; parent: [`setpgid(pid, pid)`, racing the child's `setsid`] -> `ProcessHandle`.

**`~ProcessHandle`** -> `cleanupProcess` (lock) -> detached / `pid <= 0` / `None`? return -> `waitpid(WNOHANG)` -> running? `SIGKILL` (`-pgid` if `killProcessGroup` and `getpgid(pid) == pid`, else PID) -> poll reap (5 s `Graceful` / 1 s `Immediate`, unlocking around sleeps) -> `Graceful` timeout: `SIGKILL` PID, poll 1 s -> give up; already exited? cache status.

**`ProcessHandle::wait(timeout)`** -> loop { lock; cached? return it; `waitpid(WNOHANG)`; exited: cache + return; error: cache `Unknown` + return; unlock; deadline (`timeout > 0`)? return `timedOut`; sleep 10 ms }.

---

## 6. Thread Safety Model

`ShellRunner`'s static functions share no state and may be called concurrently, with three exceptions: `executeWithInput` (one temporary file name per process, so concurrent calls collide); the `waitpid`-based helpers, which can reap a child another thread is waiting on; and `spawn()`, whose child inherits every file descriptor open without `FD_CLOEXEC` at the moment of `fork` -- a single-threaded concern too (a listening socket inherited by a helper keeps its port bound), and across threads it includes descriptors another thread just opened, such as the temporary file `executeWithInput` writes (SR-8).

`ProcessHandle` guards `_terminationStrategy`, `_detached`, and `_cachedWaitResult` with `mutable std::mutex _mutex`:

| Operation | Synchronization | Notes |
|---|---|---|
| `isRunning`, `getState` | unlocked `_pid` check, then `lock_guard(_mutex)` for the rest | Includes a `waitpid(WNOHANG)` under the lock. |
| `wait` | `_mutex` held only around each `waitpid` / cache update | Sleeps unlocked; safe with a concurrent `isRunning`. |
| `detach`, `setTerminationStrategy` | `lock_guard(_mutex)` | |
| `terminate`, `kill`, `signal`, `waitUntilReady`, `waitForCommandReady`, `pid` | none | Read `_pid` / `_command` without the lock (`pidExists()` is `kill(pid, 0)`) and do not consult the cached wait result, so a concurrent `wait()` can reap the child between the existence check and the signal. |
| destructor / move assignment (`cleanupProcess`) | `unique_lock(_mutex)`, released around each 10 ms sleep | Can block for up to about 6 s (`Graceful`). |
| move assignment transfer | `lock_guard` on the **target's** `_mutex` only | Moving from a handle another thread is using is a data race. |

Concurrent queries (`isRunning` / `getState` / `wait`) on one handle from several threads are safe and see a consistent cached result: every query path checks the cache under `_mutex` before calling `waitpid`, so only one of them reaps and the others read its result. (`cleanupProcess` does not consult the cache; see SR-11.) The `ProcessHandle thread safety` test exercises concurrent `isRunning` / `getState`, and `ProcessHandle concurrent wait keeps the reaped exit status` runs two concurrent `wait()` calls. Destroying or move-assigning a handle while another thread is using it is not safe (as for any object). `_pid` is written only by construction and move operations, so the unlocked reads are safe as long as the handle is not being moved concurrently.

**What the unlock-around-sleep allows.** In the destructor no other thread may touch the object, so releasing the lock changes nothing. During move assignment it lets other threads call into the target mid-cleanup: a concurrent `detach()` or `setTerminationStrategy()` is ignored (the process is still killed), and a concurrent `wait()` can reap the child, after which the cleanup loop does not notice and polls to its timeout (tracked as SR-11). Treat a handle being move-assigned as unavailable to other threads.

**`fork()` in a multithreaded program.** The child runs `childProcessSetup`, which builds `std::string`/`std::vector` values (heap allocation) before `exec` when `environment` is non-empty. POSIX permits only async-signal-safe calls between `fork` and `exec` in a multithreaded process. glibc (and musl 1.2.2+) make `malloc` itself usable in the child by taking its locks around `fork`, but any other lock another thread held at that moment stays held in the child, and portability is not guaranteed. Spawning from a single-threaded context (or with an empty `environment`) avoids that path.

---

## 7. Configuration Reference

### `ExecutionOptions` (`:50-58`)

| Field | Type | Default | Effect |
|---|---|---|---|
| `environment` | `unordered_map<string,string>` | empty | Prepended as unquoted `K=V ` assignments; applies to the first simple command only (see §3.1) |
| `workingDirectory` | `string` | empty | Prepended as unquoted `cd DIR && ` |
| `input` | `string` | empty | **Ignored** |
| `timeout` | `milliseconds` | `0` (none) | Bounds output reading only; does not stop the command |
| `captureStderr` | `bool` | `false` | **Ignored** |
| `throwOnError` | `bool` | `true` | Throw on `popen` failure or a non-zero, non-timed-out exit |

### `SpawnOptions` (`:64-102`)

| Field | Type | Default | Effect |
|---|---|---|---|
| `environment` | `unordered_map<string,string>` | empty (inherit) | Non-empty **replaces** the whole environment (`execve`), including `PATH` -- dash still finds bare commands through its built-in default path, but programs the child itself `execvp`s do not |
| `workingDirectory` | `string` | empty (inherit) | `chdir` in the child; `_exit(127)` on failure |
| `stdoutFile` / `stderrFile` | `string` | empty | Truncate-and-redirect fd 1 / fd 2 (mode `0644`) |
| `closeStdin` | `bool` | `false` | **Ignored**; stdin is always inherited |
| `createProcessGroup` | `bool` | `true` | Child calls `setsid()` (falls back to `setpgid(0,0)`); parent also calls `setpgid(pid, pid)`. The child always leads a new process group; whether it also gets a new session depends on a race (§3.2) |
| `killProcessGroup` | `bool` | `true` | Destructor signals `-pgid` instead of the PID, but only when the child leads its own group and is still alive at destruction; with `createProcessGroup = false` only the PID is signalled |
| `terminationStrategy` | `Graceful` / `Immediate` / `None` | `Graceful` | Destructor behavior: `SIGKILL` + 5 s (+1 s) reap / `SIGKILL` + 1 s reap / leave running |

---

## 8. API Reference

```cpp
namespace iora
{
namespace system
{

struct ExecutionResult
{
  int exitCode = 0;
  std::string stdout;
  std::string stderr;
  bool timedOut = false;
  std::chrono::milliseconds duration{0};
};

struct ExecutionOptions; // see section 7
struct SpawnOptions;     // see section 7; SpawnOptions::TerminationStrategy { Graceful, Immediate, None }

class ProcessHandle
{
public:
  enum class State { Running, Exited, Signaled, Unknown };
  struct WaitResult
  {
    bool exited = false;   // true whenever reaped, including when signalled -- use state
    int exitCode = 0;
    int signal = 0;
    bool timedOut = false;
    State state = State::Unknown;
  };

  explicit ProcessHandle(pid_t pid,
                         SpawnOptions::TerminationStrategy strategy = SpawnOptions::TerminationStrategy::Graceful,
                         bool killProcessGroup = true, const std::string &command = "");
  ~ProcessHandle() noexcept;
  ProcessHandle(ProcessHandle &&) noexcept;
  ProcessHandle &operator=(ProcessHandle &&) noexcept;

  pid_t pid() const;
  bool isRunning() const;
  State getState() const;
  WaitResult wait(std::chrono::milliseconds timeout = std::chrono::milliseconds(0));
  bool terminate();
  bool kill();
  bool signal(int sig);
  void detach();
  bool waitUntilReady(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
  bool waitForCommandReady(std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
  void setTerminationStrategy(SpawnOptions::TerminationStrategy strategy);
  static pid_t waitpidWithEINTR(pid_t pid, int *status, int options);
};

struct PcloseDeleter { void operator()(FILE *stream) const noexcept; };
inline int pcloseExitCode(int rc);

class ShellRunner
{
public:
  static std::string execute(const std::string &command);
  static int execute(const std::string &command, std::ostream &output);
  static ExecutionResult executeWithOptions(const std::string &command, const ExecutionOptions &options = {});
  static std::string executeWithInput(const std::string &command, const std::string &input);

  static ProcessHandle spawn(const std::string &command, const SpawnOptions &options = {});
  static std::vector<pid_t> findProcesses(const std::string &pattern);
  static int killProcesses(const std::string &pattern, int sig = SIGKILL,
                           std::chrono::milliseconds waitFor = std::chrono::milliseconds(200));
  static bool isProcessRunning(pid_t pid);
  static ProcessHandle::State getProcessState(pid_t pid);
  static ProcessHandle::WaitResult waitForProcess(pid_t pid,
                                                  std::chrono::milliseconds timeout = std::chrono::milliseconds(0));
  static bool sendSignal(pid_t pid, int sig);
  static bool killProcessGroup(pid_t pgid, int sig = SIGKILL);
};

} // namespace system
} // namespace iora
```

| Function | Throws |
|---|---|
| `execute(cmd)` | `std::runtime_error` on `popen` failure or non-zero exit |
| `execute(cmd, ostream)` | `std::runtime_error` on `popen` failure only |
| `executeWithOptions` | `std::runtime_error` on `popen` failure or non-zero, non-timed-out exit, when `throwOnError` |
| `executeWithInput` | `std::runtime_error` if the temp file cannot be created, `popen` fails, or the exit is non-zero |
| `spawn` | `std::runtime_error` if `fork` fails (exec failure shows up as exit code `127`); an allocation failure while building the handle, or inside the forked child, is not handled (SR-26) |
| `findProcesses`, `killProcesses` | `std::regex_error` for an invalid pattern |
| `ProcessHandle` members | no exceptions of their own; the destructor and moves are `noexcept`. Other members can in principle propagate `std::system_error` from locking the mutex, and `waitForCommandReady` can throw `std::bad_alloc` |

The public constructor accepts any PID, but a handle is only useful for a child of the calling process: for a non-child, `isRunning()` is `false` even while it runs and the destructor does nothing.

---

## 9. Design Decisions

| Decision | Rationale |
|---|---|
| Everything through `/bin/sh -c` | Callers write commands the way they would type them (pipes, redirects, `&&`); the cost is that inputs are shell-interpreted. |
| RAII handle that kills on destruction | The primary use is test fixtures: a failing assertion or exception must not leave a helper process running. |
| `SIGKILL` for `Graceful` and `terminate()` | Recorded in the code as a workaround: `SIGTERM` delivery to a shell in its own session was unreliable with `/bin/dash`, and Catch2's signal handler interfered with tests. This makes termination reliable but never graceful; the fix is tracked (backlog `2026-09-24-4`, SR-1). |
| Kill the whole process group by default, but only a group the child leads | `sh -c "a | b"` or a command that forks leaves grandchildren; signalling `-pgid` takes them down too (while the leader is alive, see SR-19). Requiring `getpgid(pid) == pid` guarantees the group is never the caller's: the caller's group ID predates the child and so can never equal the child's PID. (It can be a *sibling's* group if the handle's own child was already reaped and its PID reused; SR-11.) |
| Cache the first reaped `WaitResult` | `waitpid` can reap a child only once; caching (checked under the lock before every `waitpid` in `isRunning` / `getState` / `wait`) lets `isRunning` / `getState` / `wait` be called repeatedly and from several threads with a consistent answer. |
| `PcloseDeleter` functor and `pcloseExitCode` | The functor keeps the `unique_ptr` deleter type free of glibc's `pclose` attributes (a `-Werror` failure on GCC 14); `pcloseExitCode` stops a signal-killed command from being reported with a garbage `WEXITSTATUS`. |
| Names kept as-is | Reviewed on 2026-09-24 and documented rather than renamed: `createProcessGroup` (it calls `setsid`, but in practice yields only a new process group, SR-14), `SpawnOptions::killProcessGroup` vs the `ShellRunner::killProcessGroup()` function, the public helpers `PcloseDeleter` / `pcloseExitCode` / `waitpidWithEINTR` ("retrying on `EINTR`"), and the `iora::system` namespace, which hides `::system()` for unqualified calls inside `namespace iora`. |

---

## 10. Known Limitations

The bracketed items are defects tracked in `tasks/iora/backlog/2026-09-24-4_shell-runner-behavioral-hardening_P0.json`; this guide will be re-synced when that work lands.

- **[SR-1] No graceful termination.** `Graceful` sends `SIGKILL` immediately and only waits longer to reap; `terminate()` sends `SIGKILL` to the PID only, ignoring `killProcessGroup`. (The README section this guide replaces still says "SIGTERM first"; that was never true of this code.)
- **[SR-2] `ExecutionOptions::environment` / `workingDirectory` are unquoted and mis-scoped.** The `K=V` assignments reach only the first simple command, which is `cd` when a working directory is set; values with spaces or metacharacters break or inject.
- **[SR-3] `ExecutionOptions::timeout` does not stop the command.** `pclose` waits for the child after the read deadline; a hung command hangs the caller.
- **[SR-4] Ignored options.** `ExecutionOptions::input`, `ExecutionOptions::captureStderr`, and `SpawnOptions::closeStdin` have no effect; `ExecutionResult::stderr` is always empty.
- **[SR-5] `executeWithInput` temp file.** The name `/tmp/iora_shell_input_<pid>` is predictable and shared by all threads of a process; the file is left behind when the command exits non-zero; the write is not checked.
- **[SR-6] `waitForCommandReady()` does not wait for the command.** It matches any process whose command line contains `"sh"` and the command, which includes the `sh -c` wrapper itself.
- **[SR-7] The `waitpid`-based static helpers reap.** `isProcessRunning` / `getProcessState` / `waitForProcess` consume a child's exit status (a `ProcessHandle` for it then reports `Unknown`) and report `false` / `Unknown` for any process that is not a child of the caller.
- **[SR-8] Not async-signal-safe after `fork`.** The child allocates when `environment` is non-empty; parent file descriptors without `FD_CLOEXEC` leak into the child; the signal mask is not reset.
- **[SR-9] `ExecutionResult::stdout` / `stderr` member names** collide with the `<cstdio>` macros; they compile on glibc (which defines the macros to themselves) but not on musl.
- **[SR-10] `SpawnOptions::environment` replaces, `ExecutionOptions::environment` adds.** The same field name has opposite semantics in the two option structs.
- **[SR-11] Cleanup does not consult the cached wait result.** (a) If the child is reaped by someone else *after* the destructor's `SIGKILL` (`SIGCHLD` set to `SIG_IGN`, a `SIGCHLD` handler calling `waitpid(-1)`, or a concurrent `wait()` while move assignment's cleanup is unlocked for a sleep), `waitpid` returns `ECHILD` and the reap loop treats it as "still running": `Graceful` spins 5 s, then re-sends `SIGKILL` to a PID that may already be reused and spins 1 s more; `Immediate` spins 1 s. (A reap *before* destruction just makes cleanup return at once.) (b) If the handle already reaped its child and the PID was reused by another child of this process, destruction kills that child (its whole group, if it leads one and `killProcessGroup` is set) and steals its status (§3.3).
- **[SR-12] `WaitResult::exited` is `true` for a signal-killed process** (see §3.3).
- **[SR-13] Signalling after a reap.** `terminate()` / `kill()` / `signal()` ignore the cached wait result and take no lock, so they can signal a reused PID after the handle (or another thread) reaped the child.
- **[SR-14] New session is nondeterministic** (the `setpgid`/`setsid` race, §3.2).
- **[SR-15] Partial locking in moves.** A concurrent move can write `-1` into `_pid` between `terminate()` / `kill()` / `signal()`'s existence check and its `kill()`, turning it into `kill(-1, SIGKILL)` -- every process the user may signal. Never move a handle while another thread may signal it. Move construction locks neither side and move assignment locks only the target, and the `_pid` pre-checks run unlocked; `cleanupProcess()` is `noexcept` yet re-locks a mutex whose `lock()` may throw (which would call `std::terminate`).
- **[SR-16] Readiness helpers prove little.** `waitUntilReady()` accepts a zombie; `waitForCommandReady()` can also give a false negative once `sh` execs the command in place.
- **[SR-17] Loose ends.** The public constructor accepts any PID; `wait()` caches `Unknown` on a `waitpid` error while `isRunning()` does not; `killProcesses()` may match the caller.
- **[SR-18] `DIR*` leak on a throw.** `findProcesses` and `waitForCommandReady` pair `opendir`/`closedir` by hand; a throw in between (`std::regex_error`, `std::bad_alloc`, `std::stoi`) leaks the directory handle.
- **[SR-19] Group cleanup needs a live leader.** Once the leader has exited -- reaped by a query or by the destructor's own `waitpid` -- destruction sends nothing and remaining group members (background jobs, daemonizing children) are orphaned. Sweep while the leader is still unreaped, as in Usage example 9; after the reap there is no race-free way to target the group by ID. The handle does not do this itself.
- **[SR-20] `executeWithInput` redirects the last simple command only** (see §3.1); a command ending in a `# comment` swallows the redirect entirely.
- **[SR-21] Duplicated `/proc` scan** between `findProcesses` and `waitForCommandReady`.
- **[SR-22] A stopped child counts as running** (§3.3).
- **[SR-23] Ignored signals stay ignored in the child.** Only `SIGTERM` / `SIGINT` / `SIGHUP` are reset (and only with `createProcessGroup`); any other signal the caller ignores, such as `SIGPIPE` or `SIGCHLD`, stays ignored across `exec`.
- **[SR-24] Same file for `stdoutFile` and `stderrFile` overwrites** (§3.2).
- **[SR-26] Exceptions after `fork`.** An allocation failure while the child builds its environment unwinds through `spawn()` inside the child (a duplicate of the caller keeps running), and one while the parent builds the handle leaves the child unowned.
- **[SR-25] Relative redirect paths ignore `workingDirectory`** (§3.2).
- **Reach.** The `iora/iora.hpp` umbrella header includes `shell_runner.hpp`, so SR-9 (the `stdout` / `stderr` member names) and the `iora::system` namespace affect every consumer of the umbrella.
- **Linux only.** `/proc` scanning and `/bin/sh` are hardcoded; there is no macOS or Windows support (the README section this guide replaces still claims macOS support).
- **Output is text.** `fgets` + C-string append truncates at a `NUL` byte in the output.
- **Exit code 127 is ambiguous for `spawn`.** A failed redirect, `chdir`, or `exec` in the child exits `127`, the same code the shell uses for "command not found".
- **PID reuse.** For a PID that is not an unreaped child of the caller (the static helpers, `killProcesses`), a PID can be recycled between the check and the signal; this is inherent to PID-based POSIX process control. For a handle's own child it is avoidable, and is tracked as SR-13.
- **Destructor can block.** If a `Graceful` handle's process cannot be reaped promptly after `SIGKILL` (for example, it is stuck in uninterruptible sleep, or SR-11 applies), the destructor blocks for about 6 s before giving up.
- **Test coverage.** `tests/util/iora_test_shell_runner.cpp` (31 test cases) covers `spawn`, `wait` (including a negative timeout) and timeouts, every termination strategy (including `None` via `setTerminationStrategy`), move and `detach` (including move assignment killing the previous process), stdout/stderr redirection (including a caller with fd 1 closed), working directory (including the `_exit(127)` of a failed `chdir`), environment, process groups (the child leads its own group), the `createProcessGroup = false` destruction path for both strategies (in a forked, single-thread-checked harness in its own session, asserting the harness survives and the child was killed), grandchild cleanup through the group kill for both strategies, `killProcessGroup = false` leaving grandchildren alive, `signal()`, the moved-from `terminate` / `kill` / `signal` / `waitUntilReady` refusals, `waitUntilReady` on a live child, `findProcesses` / `killProcesses` with a per-run unique pattern (which also assert the success path of `waitForCommandReady`) and an invalid pattern, `isProcessRunning` / `getProcessState` (`Running`, `Signaled`, `Unknown` for a non-child) / `waitForProcess` (including a timeout) / `sendSignal` / `killProcessGroup` (including the refusal of groups 0 and 1), a static helper stealing a handle's exit status (`Unknown`, cached), exit codes, the cached state, three threads racing `isRunning` / `getState` across the reap, two concurrent `wait()` calls, every branch of `pcloseExitCode`, and the exit-code behavior of `execute` / `execute(ostream)` / `executeWithOptions` (both `throwOnError` settings) / `executeWithInput`. Not tested: the `executeWithOptions` timeout path, `waitForCommandReady`'s timeout path, `waitUntilReady`'s timeout path, the `ExecutionOptions` environment/working-directory composition, the `Graceful` 5 s escalation, Usage example 9, and the SR-11/SR-19/SR-22/SR-26 cases (tracked).

---

*See also:* [`../core/thread_pool.md`](../core/thread_pool.md) (for running work in-process instead of spawning).
