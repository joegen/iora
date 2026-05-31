// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// This file is part of Iora, which is licensed under the Mozilla Public
// License 2.0. See the LICENSE file or <https://www.mozilla.org/MPL/2.0/> for
// details.
//
// Asset pipeline runtime: the Assets class plus its associated value types.
// Architecture: coding_trackers/architecture/iora/asset_pipeline.json.
// Tracker: 2026-05-29-6 (htmx-support phase 5).
//
// Two modes behind one interface (LD-5):
//   - fromEmbedded(registry): production single-binary mode. Non-external paths
//     are zero-copy static-storage lookups (no lock). EXTERNAL_PATTERNS paths
//     (RD-11) are read per-request from EXTERNAL_DIR into a fresh owning handle
//     (model A: no shared cache, no mutex; fromEmbedded owns NO mutex).
//   - fromDirectory(root): dev/--asset-root mode. A per-path content+ETag cache
//     behind a single leaf mutex, populated with double-checked locking
//     (model B). Optional per-request-disk-read mode bypasses the cache.
//
// StaticBlob lifetime (RD-20 / thread H-1): filesystem and embedded-external
// blobs carry ONE std::shared_ptr<const StaticCacheEntry> (_entry) owning
// bytes + identity etag + gzip bytes + gzip etag together; all four string_view
// fields view into that single handle, so one shared_ptr copy keeps every view
// valid for the response lifetime and across a concurrent reload().
//
// SECURITY (web M-3, TOCTOU): the filesystem and EXTERNAL_DIR read paths
// resolve a path (weakly_canonical), verify component-wise containment, then
// open it. weakly_canonical defeats symlinks present at check time (an escaping
// symlink is rejected by containment); the check-then-open RACE (an attacker who
// can write into the root swapping the checked file for an escaping symlink
// before the open) is closed by readFile opening the canonical leaf with
// O_NOFOLLOW on POSIX (a swapped-in symlink leaf is refused atomically). A
// legitimate within-root symlink asset still serves because the path opened is
// the already-resolved canonical target. Residuals: Windows lacks O_NOFOLLOW
// (falls back to the documented trust-boundary contract — root not writable by
// less-trusted principals); intermediate-component swaps would need openat()
// chains (out of v1 scope).
//
// getTemplate cross-thread (H-5/N-5): getTemplate's filesystem-mode return is a
// bare std::string_view into the template cache and is NOT ownership-protected
// against a CONCURRENT reload() on another thread — callers MUST copy it into an
// owning std::string before any reload boundary (the PartialResolver bridge
// copies immediately; rendering is synchronous on the handler thread). Only
// getStatic's StaticBlob is reload-safe via _entry.

#pragma once

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <iora/crypto/secure_rng.hpp>
#include <iora/util/base64.hpp>

#if defined(__unix__) || defined(__APPLE__)
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace iora
{
namespace web
{

/// \brief Immutable, ref-counted cache value for filesystem / embedded-external
/// mode (thread H-1 single owned handle). Owns the byte buffer, the identity
/// ETag, and (when a gzip variant exists) the gzip bytes and gzip ETag, all in
/// one allocation so a single shared_ptr keeps every StaticBlob view alive.
struct StaticCacheEntry
{
  std::string bytes;
  std::string etag;
  std::optional<std::string> gzipBytes;
  std::string gzipEtag;
};

/// \brief The static-asset payload returned by Assets::getStatic.
///
/// PUBLIC read surface: bytes, mime, rawEtag, gzipBytes, gzipEtag,
/// gzipVariantExists. All response-header policy (ETag quoting, Vary, 304,
/// If-None-Match, Content-Encoding) is owned by serveStatic (RD-4), NOT here.
///
/// RD-20 / thread H-1: in EMBEDDED (non-external) mode the views point at
/// static storage and `_entry` stays null (zero-copy). In FILESYSTEM and
/// EMBEDDED-EXTERNAL-FALLBACK mode `_entry` owns all four buffers and every
/// view points into *_entry. `_entry` is the LAST-declared member (cpp17 L-N5)
/// so defaulted member-wise copy/assignment reseats ownership consistently with
/// the views. Uses defaulted copy/move; do NOT read views from a moved-from
/// StaticBlob.
struct StaticBlob
{
  std::string_view bytes;
  std::string_view mime;
  std::string_view rawEtag;
  std::optional<std::string_view> gzipBytes;
  std::string_view gzipEtag;
  bool gzipVariantExists = false;
  std::shared_ptr<const StaticCacheEntry> _entry; ///< MUST stay last-declared.
};

/// \brief Tri-state result of Assets::getStatic (RD-10). serveStatic maps
/// Rejected -> 400, NotFound -> 404, Found -> 200|304.
struct GetStaticResult
{
  enum class Status
  {
    Found,
    NotFound,
    Rejected
  };

  Status status = Status::NotFound;
  StaticBlob blob;
};

/// \brief One generated static asset (compile-time registry entry). RD-5: NO
/// mime field — MIME is resolved at runtime from the path extension. `etag` is
/// the build-time file(SHA256) hex-truncation; `gzipEtag` is the build-time
/// file(SHA256) of the .gz (M-f). Distinct from the runtime StaticCacheEntry.
struct EmbeddedAsset
{
  std::string_view path;
  std::string_view bytes;
  std::string_view etag;
  std::optional<std::string_view> gzipBytes;
  std::string_view gzipEtag;
};

/// \brief One generated template (compile-time registry entry). Templates carry
/// no MIME and are not gzip-served.
struct EmbeddedTemplate
{
  std::string_view name;
  std::string_view bytes;
};

/// \brief The generated registry instance Assets::fromEmbedded consumes. Tables
/// are flat sorted arrays (sorted by key) so the generated header needs no
/// dynamic-init containers (L-3); lookups are binary searches.
struct EmbeddedAssetRegistry
{
  const EmbeddedTemplate *templates = nullptr;
  std::size_t templatesCount = 0;
  const EmbeddedAsset *statics = nullptr;
  std::size_t staticsCount = 0;
  std::string_view externalDir;              ///< RD-11 EXTERNAL_DIR (empty if none).
  const std::string_view *externalPaths = nullptr; ///< RD-11 externalized set (sorted).
  std::size_t externalPathsCount = 0;
};

/// \brief Unified runtime lookup for templates and static blobs across embedded
/// and filesystem modes. Value type (copyable/movable): embedded mode holds a
/// non-owning registry pointer (M-a: pointer, never a reference member, so
/// copy/move-assignment is not deleted); filesystem mode holds the mutable
/// cache + leaf mutex behind a shared_ptr so the class stays copyable/movable.
///
/// Thread safety: embedded mode is lock-free (immutable after construction;
/// external-fallback reads are per-request fresh handles). Filesystem mode
/// guards its cache with a single leaf mutex. Safe publication (M-n): construct
/// the Assets instance before sharing it with worker threads (i.e. before
/// http.start()).
class Assets
{
public:
  /// \brief Production constructor wrapping a generated registry (RD-11 hybrid:
  /// EXTERNAL_PATTERNS paths fall back to a guarded EXTERNAL_DIR read).
  static Assets fromEmbedded(const EmbeddedAssetRegistry &registry)
  {
    Assets a;
    a._mode = Mode::Embedded;
    a._registry = &registry;
    return a;
  }

  /// \brief Dev/--asset-root constructor reading from a live filesystem tree.
  /// Throws std::filesystem::filesystem_error at construction if `root` does
  /// not exist or is not a directory (fail fast at startup, never in a request).
  static Assets fromDirectory(const std::filesystem::path &root, bool perRequestRead = false)
  {
    namespace fs = std::filesystem;
    fs::path canonicalRoot = fs::canonical(root); // throws if missing/not a path
    if (!fs::is_directory(canonicalRoot))
    {
      throw fs::filesystem_error("Assets::fromDirectory: not a directory",
                                 canonicalRoot,
                                 std::make_error_code(std::errc::not_a_directory));
    }
    Assets a;
    a._mode = Mode::Filesystem;
    auto state = std::make_shared<FsState>();
    state->root = canonicalRoot;
    // Canonicalize the two roots ONCE at construction (thread L-2 / perf): the
    // request hot path then uses these as the containment base directly, instead
    // of re-running weakly_canonical on the root on every getStatic call.
    std::error_code rootEc;
    state->templatesRoot = std::filesystem::weakly_canonical(canonicalRoot / "templates", rootEc);
    if (rootEc)
    {
      state->templatesRoot = canonicalRoot / "templates";
    }
    state->staticsRoot = std::filesystem::weakly_canonical(canonicalRoot / "static", rootEc);
    if (rootEc)
    {
      state->staticsRoot = canonicalRoot / "static";
    }
    state->perRequestRead = perRequestRead;
    a._fs = std::move(state);
    return a;
  }

  /// \brief Return the raw template source for `name`, or nullopt if absent.
  ///
  /// H-5/N-5: the filesystem-mode view is valid only until the next reload()
  /// and is NOT protected against a concurrent reload() on another thread —
  /// callers MUST copy it into an owning std::string before any reload boundary
  /// (the PartialResolver bridge copies immediately; rendering is synchronous).
  /// M-g: a traversal name returns nullopt (template names are server-controlled,
  /// never request-derived).
  std::optional<std::string_view> getTemplate(std::string_view name) const
  {
    if (lexicallyRejected(name))
    {
      return std::nullopt;
    }
    if (_mode == Mode::Embedded)
    {
      const EmbeddedTemplate *t = findTemplate(name);
      return t ? std::optional<std::string_view>(t->bytes) : std::nullopt;
    }
    return getTemplateFilesystem(name);
  }

  /// \brief The canonical static-asset lookup and path-traversal chokepoint
  /// (OQ-9). Operates on an ALREADY-percent-decoded path (M-c: the caller
  /// decodes exactly once; getStatic never decodes). Returns a tri-state result
  /// by value so the owning shared_ptr travels with it.
  GetStaticResult getStatic(std::string_view path) const
  {
    if (lexicallyRejected(path))
    {
      return {GetStaticResult::Status::Rejected, {}};
    }
    if (_mode == Mode::Embedded)
    {
      return getStaticEmbedded(path);
    }
    return getStaticFilesystem(path);
  }

  /// \brief Drop the filesystem cache so the next lookup re-reads from disk.
  /// Embedded mode: a literal no-op (no mutex, no state, no throw — M-o).
  /// Filesystem mode: takes the leaf mutex for the drop/replace (N3-3). RD-20:
  /// dropping entries only releases the cache's reference; in-flight StaticBlobs
  /// keep their own shared_ptr, so reload() never invalidates a live response.
  void reload()
  {
    if (_mode == Mode::Embedded)
    {
      return;
    }
    std::lock_guard<std::mutex> lock(_fs->mutex);
    _fs->staticCache.clear();
    _fs->templateCache.clear();
  }

  /// \brief Resolve a file extension to a MIME type (RD-5 single source of
  /// truth). Always returns a static-storage view; unknown -> octet-stream.
  static std::string_view mimeForExtension(std::string_view path)
  {
    struct Entry
    {
      std::string_view ext;
      std::string_view mime;
    };
    // Listed once; lookup is a case-insensitive linear scan over ~24 entries.
    static constexpr Entry kTable[] = {
      {".html", "text/html; charset=utf-8"},
      {".htm", "text/html; charset=utf-8"},
      {".css", "text/css"},
      {".js", "text/javascript"},
      {".mjs", "text/javascript"},
      {".json", "application/json"},
      {".map", "application/json"},
      {".svg", "image/svg+xml"},
      {".png", "image/png"},
      {".jpg", "image/jpeg"},
      {".jpeg", "image/jpeg"},
      {".gif", "image/gif"},
      {".webp", "image/webp"},
      {".avif", "image/avif"},
      {".ico", "image/x-icon"},
      {".woff2", "font/woff2"},
      {".woff", "font/woff"},
      {".ttf", "font/ttf"},
      {".otf", "font/otf"},
      {".txt", "text/plain; charset=utf-8"},
      {".xml", "application/xml; charset=utf-8"},
    };
    static constexpr std::string_view kDefault = "application/octet-stream";

    const std::string_view ext = extensionOf(path);
    if (ext.empty())
    {
      return kDefault;
    }
    for (const Entry &e : kTable)
    {
      if (equalsIgnoreCase(ext, e.ext))
      {
        return e.mime;
      }
    }
    return kDefault;
  }

private:
  enum class Mode
  {
    Embedded,
    Filesystem
  };

  /// \brief Mutable filesystem-mode state, held behind a shared_ptr so Assets
  /// stays copyable/movable. The mutex is a LEAF lock: no other lock is acquired
  /// while it is held, and no user callback is invoked under it.
  struct FsState
  {
    std::filesystem::path root;
    std::filesystem::path templatesRoot;
    std::filesystem::path staticsRoot;
    bool perRequestRead = false;
    mutable std::mutex mutex; ///< leaf lock (filesystem mode only).
    std::unordered_map<std::string, std::shared_ptr<const StaticCacheEntry>> staticCache;
    std::unordered_map<std::string, std::shared_ptr<const std::string>> templateCache;
  };

  Mode _mode = Mode::Embedded;
  const EmbeddedAssetRegistry *_registry = nullptr; ///< embedded mode (non-owning).
  std::shared_ptr<FsState> _fs;                     ///< filesystem mode.

  // ---- lexical / path helpers -------------------------------------------

  /// \brief OQ-9 lexical rejection: a '..' path segment, a leading '/', a NUL
  /// byte, or a backslash. Runs before any filesystem read.
  static bool lexicallyRejected(std::string_view p)
  {
    if (p.empty())
    {
      return false; // empty -> falls through to a miss (NotFound)
    }
    if (p.front() == '/')
    {
      return true;
    }
    if (p.find('\0') != std::string_view::npos)
    {
      return true;
    }
    if (p.find('\\') != std::string_view::npos)
    {
      return true;
    }
    std::size_t start = 0;
    while (true)
    {
      std::size_t slash = p.find('/', start);
      std::string_view seg =
        (slash == std::string_view::npos) ? p.substr(start) : p.substr(start, slash - start);
      if (seg == "..")
      {
        return true;
      }
      if (slash == std::string_view::npos)
      {
        break;
      }
      start = slash + 1;
    }
    return false;
  }

  /// \brief Extension (including the leading '.') of the last path segment, or
  /// empty if none.
  static std::string_view extensionOf(std::string_view path)
  {
    std::size_t slash = path.find_last_of('/');
    std::string_view leaf = (slash == std::string_view::npos) ? path : path.substr(slash + 1);
    std::size_t dot = leaf.find_last_of('.');
    if (dot == std::string_view::npos || dot == 0)
    {
      return {};
    }
    return leaf.substr(dot);
  }

  static bool equalsIgnoreCase(std::string_view a, std::string_view b)
  {
    if (a.size() != b.size())
    {
      return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
      char ca = a[i];
      char cb = b[i];
      if (ca >= 'A' && ca <= 'Z')
      {
        ca = static_cast<char>(ca - 'A' + 'a');
      }
      if (cb >= 'A' && cb <= 'Z')
      {
        cb = static_cast<char>(cb - 'A' + 'a');
      }
      if (ca != cb)
      {
        return false;
      }
    }
    return true;
  }

  /// \brief Component-wise containment check (M-d): `target` must be at or below
  /// `base`. NOT a string starts_with test (which admits sibling-prefix escapes).
  static bool isContained(const std::filesystem::path &base, const std::filesystem::path &target)
  {
    std::filesystem::path rel = target.lexically_relative(base);
    if (rel.empty())
    {
      return false;
    }
    auto it = rel.begin();
    if (it == rel.end())
    {
      return false;
    }
    return *it != std::filesystem::path("..");
  }

  // ---- file / etag helpers ----------------------------------------------

  // Reads an ALREADY-CANONICALIZED, containment-checked path. web M-3 (TOCTOU):
  // on POSIX the leaf is opened with O_NOFOLLOW so a file that was swapped for a
  // symlink between the containment check and the open is refused atomically —
  // closing the check-then-open race. Because the path passed here is the
  // weakly_canonical result (symlinks already resolved), a LEGITIMATE within-root
  // symlink asset still serves: it was resolved to its canonical non-symlink
  // target before this open. (Windows lacks O_NOFOLLOW -> documented residual;
  // intermediate-component swaps would additionally need openat() chains.)
  static std::optional<std::string> readFile(const std::filesystem::path &p)
  {
#if defined(__unix__) || defined(__APPLE__)
    int fd = ::open(p.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
      return std::nullopt; // ELOOP (symlinked leaf), ENOENT, EACCES, ...
    }
    // RAII guard: close the fd on every exit path, including an exception from
    // std::string growth (L-1 exception-safety).
    struct FdGuard
    {
      int fd;
      ~FdGuard() { ::close(fd); }
    } guard{fd};
    std::string data;
    std::vector<char> buf(65536); // heap, not a 64 KB stack frame
    for (;;)
    {
      ssize_t n = ::read(fd, buf.data(), buf.size());
      if (n > 0)
      {
        data.append(buf.data(), static_cast<std::size_t>(n));
      }
      else if (n == 0)
      {
        break; // EOF
      }
      else if (errno == EINTR)
      {
        continue;
      }
      else
      {
        return std::nullopt;
      }
    }
    return data;
#else
    std::ifstream f(p, std::ios::binary);
    if (!f)
    {
      return std::nullopt;
    }
    std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (f.bad())
    {
      return std::nullopt;
    }
    return data;
#endif
  }

  /// \brief Runtime ETag: 16-byte-truncated SHA-256, Base64Url-encoded, unquoted.
  static std::string computeEtag(const std::string &bytes)
  {
    unsigned char digest[32];
    iora::crypto::SecureRng::sha256(bytes, digest);
    return iora::util::Base64Url::encode(digest, 16);
  }

  /// \brief Build an owning cache entry from an on-disk file (identity bytes +
  /// optional sibling .gz variant), computing both ETags at runtime.
  static std::shared_ptr<StaticCacheEntry> buildEntry(const std::filesystem::path &file)
  {
    auto bytes = readFile(file);
    if (!bytes)
    {
      return nullptr;
    }
    auto entry = std::make_shared<StaticCacheEntry>();
    entry->bytes = std::move(*bytes);
    entry->etag = computeEtag(entry->bytes);

    std::filesystem::path gz = file;
    gz += ".gz";
    std::error_code ec;
    if (std::filesystem::is_regular_file(gz, ec))
    {
      auto gzBytes = readFile(gz);
      if (gzBytes)
      {
        entry->gzipEtag = computeEtag(*gzBytes);
        entry->gzipBytes = std::move(*gzBytes);
      }
    }
    return entry;
  }

  /// \brief Build a StaticBlob whose views point into the owned *entry (M-N2:
  /// gzipBytes engaged iff entry->gzipBytes engaged, viewed from the contained
  /// string). The shared_ptr is moved in so ownership travels with the blob.
  static StaticBlob blobFromEntry(std::shared_ptr<const StaticCacheEntry> entry,
                                  std::string_view path)
  {
    StaticBlob b;
    b._entry = std::move(entry);
    b.bytes = b._entry->bytes;
    b.mime = mimeForExtension(path);
    b.rawEtag = b._entry->etag;
    if (b._entry->gzipBytes)
    {
      b.gzipBytes = std::string_view(*b._entry->gzipBytes);
      b.gzipEtag = b._entry->gzipEtag;
      b.gzipVariantExists = true;
    }
    return b;
  }

  // ---- embedded-mode lookups --------------------------------------------

  const EmbeddedAsset *findStatic(std::string_view path) const
  {
    const EmbeddedAsset *begin = _registry->statics;
    const EmbeddedAsset *end = begin + _registry->staticsCount;
    const EmbeddedAsset *it =
      std::lower_bound(begin, end, path,
                       [](const EmbeddedAsset &a, std::string_view p) { return a.path < p; });
    if (it != end && it->path == path)
    {
      return it;
    }
    return nullptr;
  }

  const EmbeddedTemplate *findTemplate(std::string_view name) const
  {
    const EmbeddedTemplate *begin = _registry->templates;
    const EmbeddedTemplate *end = begin + _registry->templatesCount;
    const EmbeddedTemplate *it =
      std::lower_bound(begin, end, name,
                       [](const EmbeddedTemplate &t, std::string_view n) { return t.name < n; });
    if (it != end && it->name == name)
    {
      return it;
    }
    return nullptr;
  }

  bool isExternalPath(std::string_view path) const
  {
    const std::string_view *begin = _registry->externalPaths;
    const std::string_view *end = begin + _registry->externalPathsCount;
    return std::binary_search(begin, end, path);
  }

  static StaticBlob embeddedBlob(const EmbeddedAsset &a, std::string_view path)
  {
    StaticBlob b;
    b.bytes = a.bytes;
    b.mime = mimeForExtension(path);
    b.rawEtag = a.etag;
    if (a.gzipBytes)
    {
      b.gzipBytes = a.gzipBytes;
      b.gzipEtag = a.gzipEtag;
      b.gzipVariantExists = true;
    }
    // _entry stays null: zero-copy static-storage views.
    return b;
  }

  GetStaticResult getStaticEmbedded(std::string_view path) const
  {
    const EmbeddedAsset *a = findStatic(path);
    if (a != nullptr)
    {
      return {GetStaticResult::Status::Found, embeddedBlob(*a, path)};
    }
    if (!_registry->externalDir.empty() && isExternalPath(path))
    {
      // Model A: per-request fresh local handle from EXTERNAL_DIR. No cache,
      // no mutex (fromEmbedded stays lock-free).
      namespace fs = std::filesystem;
      fs::path externalDir(std::string(_registry->externalDir));
      std::error_code ec;
      fs::path base = fs::weakly_canonical(externalDir, ec);
      if (ec)
      {
        return {GetStaticResult::Status::NotFound, {}};
      }
      fs::path candidate = externalDir / fs::path(std::string(path));
      fs::path resolved = fs::weakly_canonical(candidate, ec);
      if (ec)
      {
        return {GetStaticResult::Status::NotFound, {}};
      }
      if (!isContained(base, resolved))
      {
        return {GetStaticResult::Status::Rejected, {}};
      }
      if (!fs::is_regular_file(resolved, ec))
      {
        return {GetStaticResult::Status::NotFound, {}};
      }
      std::shared_ptr<StaticCacheEntry> entry = buildEntry(resolved);
      if (!entry)
      {
        return {GetStaticResult::Status::NotFound, {}};
      }
      return {GetStaticResult::Status::Found, blobFromEntry(std::move(entry), path)};
    }
    return {GetStaticResult::Status::NotFound, {}};
  }

  // ---- filesystem-mode lookups ------------------------------------------

  GetStaticResult getStaticFilesystem(std::string_view path) const
  {
    namespace fs = std::filesystem;
    std::error_code ec;
    // staticsRoot was canonicalized once at construction (the containment base).
    const fs::path &base = _fs->staticsRoot;
    fs::path candidate = _fs->staticsRoot / fs::path(std::string(path));
    fs::path resolved = fs::weakly_canonical(candidate, ec);
    if (ec)
    {
      return {GetStaticResult::Status::NotFound, {}};
    }
    if (!isContained(base, resolved))
    {
      return {GetStaticResult::Status::Rejected, {}};
    }
    if (!fs::is_regular_file(resolved, ec))
    {
      return {GetStaticResult::Status::NotFound, {}};
    }

    // Per-request mode (model A): fresh local handle, no shared cache.
    if (_fs->perRequestRead)
    {
      std::shared_ptr<StaticCacheEntry> entry = buildEntry(resolved);
      if (!entry)
      {
        return {GetStaticResult::Status::NotFound, {}};
      }
      return {GetStaticResult::Status::Found, blobFromEntry(std::move(entry), path)};
    }

    // Cached mode (model B): double-checked locking (H-3). Copy the shared_ptr
    // out under the lock before unlocking (RD-20).
    const std::string key(path);
    {
      std::lock_guard<std::mutex> lock(_fs->mutex);
      auto it = _fs->staticCache.find(key);
      if (it != _fs->staticCache.end())
      {
        return {GetStaticResult::Status::Found, blobFromEntry(it->second, path)};
      }
    }
    // Miss: read + hash OUTSIDE the lock.
    std::shared_ptr<StaticCacheEntry> built = buildEntry(resolved);
    if (!built)
    {
      return {GetStaticResult::Status::NotFound, {}};
    }
    std::shared_ptr<const StaticCacheEntry> chosen = built;
    {
      std::lock_guard<std::mutex> lock(_fs->mutex);
      auto it = _fs->staticCache.find(key);
      if (it != _fs->staticCache.end())
      {
        chosen = it->second; // another thread won; discard `built`.
      }
      else
      {
        _fs->staticCache.emplace(key, chosen);
      }
    }
    return {GetStaticResult::Status::Found, blobFromEntry(chosen, path)};
  }

  std::optional<std::string_view> getTemplateFilesystem(std::string_view name) const
  {
    namespace fs = std::filesystem;
    std::error_code ec;
    // templatesRoot was canonicalized once at construction (the containment base).
    const fs::path &base = _fs->templatesRoot;
    fs::path candidate = _fs->templatesRoot / fs::path(std::string(name));
    fs::path resolved = fs::weakly_canonical(candidate, ec);
    if (ec || !isContained(base, resolved))
    {
      return std::nullopt;
    }
    if (!fs::is_regular_file(resolved, ec))
    {
      return std::nullopt;
    }

    const std::string key(name);
    {
      std::lock_guard<std::mutex> lock(_fs->mutex);
      auto it = _fs->templateCache.find(key);
      if (it != _fs->templateCache.end())
      {
        return std::string_view(*it->second);
      }
    }
    auto data = readFile(resolved);
    if (!data)
    {
      return std::nullopt;
    }
    auto source = std::make_shared<std::string>(std::move(*data));
    {
      std::lock_guard<std::mutex> lock(_fs->mutex);
      auto it = _fs->templateCache.find(key);
      if (it != _fs->templateCache.end())
      {
        return std::string_view(*it->second);
      }
      _fs->templateCache.emplace(key, source);
    }
    return std::string_view(*source);
  }
};

} // namespace web
} // namespace iora
