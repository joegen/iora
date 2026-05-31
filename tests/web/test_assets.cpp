// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Unit tests for iora::web::Assets (web/assets.hpp).
// Tracker: 2026-05-29-6 (htmx-support phase 5); architecture: asset_pipeline.json.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <iora/web/assets.hpp>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using iora::web::Assets;
using iora::web::EmbeddedAsset;
using iora::web::EmbeddedAssetRegistry;
using iora::web::EmbeddedTemplate;
using iora::web::GetStaticResult;
using iora::web::StaticBlob;

namespace
{
namespace fs = std::filesystem;

// ---- on-disk fixture helpers ------------------------------------------------

struct TempTree
{
  fs::path root;

  explicit TempTree(const std::string &name)
  {
    root = fs::temp_directory_path() / ("iora_assets_" + name);
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root / "templates");
    fs::create_directories(root / "static");
  }

  ~TempTree()
  {
    std::error_code ec;
    fs::remove_all(root, ec);
  }

  void writeStatic(const std::string &rel, const std::string &content) const
  {
    fs::path p = root / "static" / rel;
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << content;
  }

  void writeTemplate(const std::string &rel, const std::string &content) const
  {
    fs::path p = root / "templates" / rel;
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << content;
  }
};

// ---- embedded fixture registry ---------------------------------------------
// Tables MUST be sorted by key (the codegen emits sorted; lookups binary-search).

constexpr std::string_view kCssBytes = "body{color:red}";
// 32 hex chars = the documented embedded ETag format (build-time SHA-256 trunc).
constexpr std::string_view kCssEtag = "0123456789abcdef0123456789abcdef";
constexpr std::string_view kJsBytes = "console.log(1)";
constexpr std::string_view kJsEtag = "fedcba9876543210fedcba9876543210";
// M-6: declare binary gzip fixture with an EXPLICIT length (and an embedded NUL)
// so a string_view-from-literal cannot silently truncate at the NUL — mirroring
// how the real generator emits string_view(ptr, byteLen).
constexpr char kJsGzipData[] = {'\x1f', '\x8b', '\x08', '\x00', 'z', 'j', 's'};
constexpr std::string_view kJsGzip(kJsGzipData, sizeof(kJsGzipData));
// Embedded etags are OPAQUE registry literals (the codegen emits a build-time
// SHA-256; Assets does NOT recompute them at runtime). These hand-written values
// only test pass-through + rawEtag/gzipEtag distinctness, not the hash itself.
constexpr std::string_view kJsGzipEtag = "aaaa1111bbbb2222cccc3333dddd4444";

const EmbeddedAsset kStatics[] = {
  // sorted by path
  {"app.css", kCssBytes, kCssEtag, std::nullopt, {}},
  {"app.js", kJsBytes, kJsEtag, std::optional<std::string_view>(kJsGzip), kJsGzipEtag},
};

constexpr std::string_view kIndexTpl = "<h1>{{title}}</h1>";
const EmbeddedTemplate kTemplates[] = {
  {"index.html", kIndexTpl},
};

EmbeddedAssetRegistry makeRegistry()
{
  EmbeddedAssetRegistry r;
  r.templates = kTemplates;
  r.templatesCount = 1;
  r.statics = kStatics;
  r.staticsCount = 2;
  return r;
}
} // namespace

TEST_CASE("Assets::mimeForExtension covers the RD-5 table", "[assets][mime]")
{
  REQUIRE(Assets::mimeForExtension("a.html") == "text/html; charset=utf-8");
  REQUIRE(Assets::mimeForExtension("a.htm") == "text/html; charset=utf-8");
  REQUIRE(Assets::mimeForExtension("a.css") == "text/css");
  REQUIRE(Assets::mimeForExtension("a.js") == "text/javascript");   // RFC 9239
  REQUIRE(Assets::mimeForExtension("a.mjs") == "text/javascript");  // web L-3 own case
  REQUIRE(Assets::mimeForExtension("a.json") == "application/json");
  REQUIRE(Assets::mimeForExtension("a.map") == "application/json"); // H-g
  REQUIRE(Assets::mimeForExtension("a.svg") == "image/svg+xml");
  REQUIRE(Assets::mimeForExtension("a.png") == "image/png");
  REQUIRE(Assets::mimeForExtension("a.jpg") == "image/jpeg");
  REQUIRE(Assets::mimeForExtension("a.jpeg") == "image/jpeg");
  REQUIRE(Assets::mimeForExtension("a.gif") == "image/gif");
  REQUIRE(Assets::mimeForExtension("a.webp") == "image/webp");
  REQUIRE(Assets::mimeForExtension("a.avif") == "image/avif");
  REQUIRE(Assets::mimeForExtension("a.ico") == "image/x-icon");
  REQUIRE(Assets::mimeForExtension("a.woff2") == "font/woff2");
  REQUIRE(Assets::mimeForExtension("a.woff") == "font/woff");
  REQUIRE(Assets::mimeForExtension("a.ttf") == "font/ttf");
  REQUIRE(Assets::mimeForExtension("a.otf") == "font/otf");
  REQUIRE(Assets::mimeForExtension("a.txt") == "text/plain; charset=utf-8");
  REQUIRE(Assets::mimeForExtension("a.xml") == "application/xml; charset=utf-8");
  // case-insensitive
  REQUIRE(Assets::mimeForExtension("A.PNG") == "image/png");
  // unknown / none -> octet-stream
  REQUIRE(Assets::mimeForExtension("a.unknownext") == "application/octet-stream");
  REQUIRE(Assets::mimeForExtension("noextension") == "application/octet-stream");
  REQUIRE(Assets::mimeForExtension("css/sub/app.css") == "text/css");
  // web M-1 edge cases: double extension uses the last; dotfile + trailing dot
  // + dot-in-directory have no leaf extension -> octet-stream.
  REQUIRE(Assets::mimeForExtension("app.min.js") == "text/javascript");
  REQUIRE(Assets::mimeForExtension("archive.tar.gz") == "application/octet-stream");
  REQUIRE(Assets::mimeForExtension(".gitignore") == "application/octet-stream");
  REQUIRE(Assets::mimeForExtension("app.") == "application/octet-stream");
  REQUIRE(Assets::mimeForExtension("dir.with.dot/file") == "application/octet-stream");
}

TEST_CASE("fromEmbedded getTemplate/getStatic basic behavior", "[assets][embedded]")
{
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets a = Assets::fromEmbedded(reg);

  // getTemplate hit/miss
  auto tpl = a.getTemplate("index.html");
  REQUIRE(tpl.has_value());
  REQUIRE(*tpl == kIndexTpl);
  REQUIRE_FALSE(a.getTemplate("missing.html").has_value());

  // getStatic Found with bytes/mime/rawEtag; _entry null (zero-copy)
  GetStaticResult css = a.getStatic("app.css");
  REQUIRE(css.status == GetStaticResult::Status::Found);
  REQUIRE(css.blob.bytes == kCssBytes);
  REQUIRE(css.blob.mime == "text/css");
  REQUIRE(css.blob.rawEtag == kCssEtag);
  REQUIRE(css.blob._entry == nullptr);
  REQUIRE_FALSE(css.blob.gzipVariantExists);

  // .js -> text/javascript, distinct gzipEtag
  GetStaticResult js = a.getStatic("app.js");
  REQUIRE(js.status == GetStaticResult::Status::Found);
  REQUIRE(js.blob.mime == "text/javascript");
  REQUIRE(js.blob.gzipVariantExists);
  REQUIRE(js.blob.gzipBytes.has_value());
  REQUIRE(*js.blob.gzipBytes == kJsGzip);
  REQUIRE(js.blob.gzipEtag == kJsGzipEtag);
  REQUIRE(js.blob.gzipEtag != js.blob.rawEtag); // M-f distinct validators

  // miss -> NotFound
  REQUIRE(a.getStatic("nope.css").status == GetStaticResult::Status::NotFound);
}

TEST_CASE("Embedded ETag format is the build-time hex form (L-3)", "[assets][embedded][etag]")
{
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets a = Assets::fromEmbedded(reg);
  GetStaticResult css = a.getStatic("app.css");
  REQUIRE(css.status == GetStaticResult::Status::Found);
  // 32 hex chars, unquoted
  REQUIRE(css.blob.rawEtag.size() == 32);
  REQUIRE(css.blob.rawEtag.front() != '"');
  REQUIRE(css.blob.rawEtag.back() != '"');
  for (char c : css.blob.rawEtag)
  {
    bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    REQUIRE(hex);
  }
}

TEST_CASE("getStatic tri-state: Found / NotFound / Rejected", "[assets][traversal]")
{
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets a = Assets::fromEmbedded(reg);
  REQUIRE(a.getStatic("app.css").status == GetStaticResult::Status::Found);
  REQUIRE(a.getStatic("genuine-miss.css").status == GetStaticResult::Status::NotFound);
  REQUIRE(a.getStatic("../etc/passwd").status == GetStaticResult::Status::Rejected);
}

TEST_CASE("Lexical traversal rejection vectors (OQ-9 / M-h)", "[assets][traversal]")
{
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets a = Assets::fromEmbedded(reg);
  // All -> Rejected (literal '..' segment, leading '/', NUL, backslash)
  REQUIRE(a.getStatic("../etc/passwd").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("foo/../../bar").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("/abs").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic(std::string_view("a\0b", 3)).status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("foo\\bar").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("..\\..\\x").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("C:\\windows").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("\\\\server\\share").status == GetStaticResult::Status::Rejected);
  // Encoded vectors are literal filename bytes (caller decodes; getStatic does not)
  // -> NotFound, never Found-outside-root.
  REQUIRE(a.getStatic("%2e%2e%2fetc").status == GetStaticResult::Status::NotFound);
  // '....//' has no '..' segment -> NotFound (not Rejected, not Found-outside-root)
  REQUIRE(a.getStatic("....//x").status == GetStaticResult::Status::NotFound);
}

TEST_CASE("fromDirectory basic behavior + missing dir throws", "[assets][filesystem]")
{
  TempTree tree("basic");
  tree.writeStatic("app.css", "body{color:blue}");
  tree.writeTemplate("page.html", "<p>{{x}}</p>");

  Assets a = Assets::fromDirectory(tree.root);

  GetStaticResult css = a.getStatic("app.css");
  REQUIRE(css.status == GetStaticResult::Status::Found);
  REQUIRE(css.blob.bytes == "body{color:blue}");
  REQUIRE(css.blob.mime == "text/css");
  REQUIRE(css.blob._entry != nullptr); // filesystem mode owns the buffer

  auto tpl = a.getTemplate("page.html");
  REQUIRE(tpl.has_value());
  REQUIRE(*tpl == "<p>{{x}}</p>");

  REQUIRE(a.getStatic("missing.css").status == GetStaticResult::Status::NotFound);

  // Missing directory -> throws at construction.
  REQUIRE_THROWS_AS(Assets::fromDirectory(tree.root / "does-not-exist"),
                    fs::filesystem_error);
}

TEST_CASE("Filesystem ETag is unquoted base64url, stable, content-sensitive", "[assets][filesystem][etag]")
{
  TempTree tree("etag");
  tree.writeStatic("a.txt", "hello");
  tree.writeStatic("b.txt", "world!!");

  Assets a = Assets::fromDirectory(tree.root);
  GetStaticResult r1 = a.getStatic("a.txt");
  GetStaticResult r1b = a.getStatic("a.txt");
  GetStaticResult r2 = a.getStatic("b.txt");
  REQUIRE(r1.status == GetStaticResult::Status::Found);

  // stable across calls (cached), content-sensitive across files
  std::string e1(r1.blob.rawEtag);
  std::string e1b(r1b.blob.rawEtag);
  std::string e2(r2.blob.rawEtag);
  REQUIRE(e1 == e1b);
  REQUIRE(e1 != e2);

  // unquoted + every byte is a valid RFC 9110 etagc (base64url alphabet here)
  REQUIRE(e1.front() != '"');
  REQUIRE(e1.back() != '"');
  for (char c : e1)
  {
    bool ok = (c >= 0x21 && c <= 0x7E) && c != '"' && c != '\\';
    REQUIRE(ok);
  }
}

TEST_CASE("reload() embedded no-op; filesystem picks up new content", "[assets][reload]")
{
  // Embedded reload is a no-op and does not throw.
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets emb = Assets::fromEmbedded(reg);
  REQUIRE_NOTHROW(emb.reload());

  TempTree tree("reload");
  tree.writeStatic("a.txt", "first");
  Assets a = Assets::fromDirectory(tree.root);
  GetStaticResult before = a.getStatic("a.txt");
  REQUIRE(before.blob.bytes == "first");
  std::string firstEtag(before.blob.rawEtag);

  tree.writeStatic("a.txt", "second-content");
  a.reload();
  GetStaticResult after = a.getStatic("a.txt");
  REQUIRE(after.blob.bytes == "second-content");
  REQUIRE(std::string(after.blob.rawEtag) != firstEtag);
}

TEST_CASE("RD-20: held StaticBlob survives reload() (no UAF, full-byte read)", "[assets][reload][lifetime]")
{
  TempTree tree("lifetime");
  tree.writeStatic("a.txt", "original-bytes");
  Assets a = Assets::fromDirectory(tree.root);

  GetStaticResult held = a.getStatic("a.txt");
  REQUIRE(held.status == GetStaticResult::Status::Found);
  REQUIRE(held.blob._entry != nullptr);
  std::string originalBytes(held.blob.bytes);
  std::string originalEtag(held.blob.rawEtag);

  // Mutate + reload (drops the cache entry).
  tree.writeStatic("a.txt", "totally-different-content");
  a.reload();

  // Force a full-byte read of the held views; the held shared_ptr keeps the
  // old buffer alive (ASAN would flag a UAF here if the views dangled).
  REQUIRE(std::string(held.blob.bytes) == originalBytes);
  REQUIRE(std::string(held.blob.rawEtag) == originalEtag);
}

TEST_CASE("RD-11 embedded-external fallback reads from EXTERNAL_DIR (model A)", "[assets][embedded][external]")
{
  TempTree tree("external");
  // The external file lives directly under the external dir (not under static/).
  fs::path extDir = tree.root / "ext";
  fs::create_directories(extDir);
  std::ofstream(extDir / "big.png", std::ios::binary) << "PNGDATA";

  // externalDir string must outlive the registry use.
  std::string extDirStr = extDir.string();
  std::string_view extPaths[] = {"big.png"};

  EmbeddedAssetRegistry reg = makeRegistry();
  reg.externalDir = extDirStr;
  reg.externalPaths = extPaths;
  reg.externalPathsCount = 1;

  Assets a = Assets::fromEmbedded(reg);
  GetStaticResult png = a.getStatic("big.png");
  REQUIRE(png.status == GetStaticResult::Status::Found);
  REQUIRE(png.blob.bytes == "PNGDATA");
  REQUIRE(png.blob.mime == "image/png");
  REQUIRE(png.blob._entry != nullptr); // owned per-request handle
  // runtime base64url etag (not the hex embedded form)
  REQUIRE(png.blob.rawEtag.size() > 0);

  // an external path whose file is missing -> NotFound
  std::string_view extPaths2[] = {"big.png", "gone.png"};
  reg.externalPaths = extPaths2;
  reg.externalPathsCount = 2;
  Assets a2 = Assets::fromEmbedded(reg);
  REQUIRE(a2.getStatic("gone.png").status == GetStaticResult::Status::NotFound);
}

// SANITIZER GATE (asset_pipeline.json sanitizerBuildNote): the [assets][concurrency]
// cases below are designed to be run under TSAN and ASAN. iora has no built-in
// sanitizer target; build a separate dir with -fsanitize=thread / -fsanitize=address
// and (WSL2) run via `setarch $(uname -m) -R <exe>` to disable ASLR. Worker threads
// record outcomes into std::atomic flags; all Catch2 assertions run on the main
// thread after join() (Catch2 v2 macros are NOT thread-safe).
TEST_CASE("Concurrent cold-miss double-populate same path (thread M-3)", "[assets][concurrency]")
{
  TempTree tree("coldmiss");
  tree.writeStatic("shared.txt", "shared-content-xyz");
  Assets a = Assets::fromDirectory(tree.root);

  constexpr int kThreads = 8;
  std::vector<std::string> bytesSeen(kThreads);
  std::vector<std::string> etagsSeen(kThreads);
  std::vector<std::thread> ts;
  std::atomic<int> ready{0};
  for (int i = 0; i < kThreads; ++i)
  {
    ts.emplace_back([&, i]() {
      ++ready;
      while (ready.load() < kThreads) {} // line up for a real race on the cold path
      GetStaticResult r = a.getStatic("shared.txt");
      if (r.status == GetStaticResult::Status::Found)
      {
        bytesSeen[i] = std::string(r.blob.bytes);   // full-byte read
        etagsSeen[i] = std::string(r.blob.rawEtag);
      }
    });
  }
  for (auto &t : ts)
  {
    t.join();
  }
  // All threads see byte-identical content + etag; no crash/race.
  for (int i = 0; i < kThreads; ++i)
  {
    REQUIRE(bytesSeen[i] == "shared-content-xyz");
    REQUIRE(etagsSeen[i] == etagsSeen[0]);
  }
  // thread M-1: the double-checked locking must leave EXACTLY ONE cached entry
  // (not a last-writer-wins overwrite or a per-thread duplicate). Two post-join
  // reads must return the SAME underlying StaticCacheEntry pointer, proving a
  // single shared cached entry rather than a freshly-rebuilt one.
  GetStaticResult p1 = a.getStatic("shared.txt");
  GetStaticResult p2 = a.getStatic("shared.txt");
  REQUIRE(p1.blob._entry != nullptr);
  REQUIRE(p1.blob._entry.get() == p2.blob._entry.get());
}

TEST_CASE("Reader + reload() stress on same path (RD-20, no UAF)", "[assets][concurrency]")
{
  TempTree tree("readerreload");
  tree.writeStatic("a.txt", "content-A");
  Assets a = Assets::fromDirectory(tree.root);

  std::atomic<bool> stop{false};
  std::atomic<int> reads{0};
  // Catch2 v2 assertion macros are NOT thread-safe — worker threads record into
  // atomics; ALL assertions run on the main thread after join().
  std::atomic<bool> bad{false};

  std::thread reader([&]() {
    while (!stop.load())
    {
      GetStaticResult r = a.getStatic("a.txt");
      if (r.status == GetStaticResult::Status::Found)
      {
        // Hold the blob, then force a full-byte read AFTER a possible reload:
        // the held _entry shared_ptr must keep the buffer alive (no UAF).
        std::string copyBytes(r.blob.bytes);
        std::string copyEtag(r.blob.rawEtag);
        if (copyBytes.size() != r.blob.bytes.size() || copyEtag.empty())
        {
          bad.store(true);
        }
        ++reads;
      }
    }
  });
  std::thread writer([&]() {
    for (int i = 0; i < 200; ++i)
    {
      a.reload();
    }
  });
  writer.join();
  // Wait (BOUNDED — can never hang) for the reader to have done at least one
  // successful read before stopping, so the liveness assertion is meaningful.
  for (int g = 0; reads.load() == 0 && g < 2000000; ++g)
  {
    std::this_thread::yield();
  }
  stop.store(true);
  reader.join();
  REQUIRE_FALSE(bad.load());
  REQUIRE(reads.load() > 0);
}

TEST_CASE("Per-request-disk-read mode bypasses the cache", "[assets][concurrency][perrequest]")
{
  TempTree tree("perrequest");
  tree.writeStatic("a.txt", "v1");
  Assets a = Assets::fromDirectory(tree.root, /*perRequestRead=*/true);

  GetStaticResult r1 = a.getStatic("a.txt");
  REQUIRE(r1.blob.bytes == "v1");

  // No reload() needed: per-request mode reads fresh every call.
  tree.writeStatic("a.txt", "v2-fresh");
  GetStaticResult r2 = a.getStatic("a.txt");
  REQUIRE(r2.blob.bytes == "v2-fresh");

  // concurrent readers in per-request mode -> race-free (each builds a local handle)
  std::vector<std::thread> ts;
  std::atomic<int> ok{0};
  for (int i = 0; i < 6; ++i)
  {
    ts.emplace_back([&]() {
      GetStaticResult r = a.getStatic("a.txt");
      if (r.status == GetStaticResult::Status::Found && std::string(r.blob.bytes) == "v2-fresh")
      {
        ++ok;
      }
    });
  }
  for (auto &t : ts)
  {
    t.join();
  }
  REQUIRE(ok.load() == 6);
}

TEST_CASE("Embedded getStatic + reload() concurrently is lock-free safe (M-7)", "[assets][concurrency][embedded]")
{
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets a = Assets::fromEmbedded(reg);
  std::atomic<bool> stop{false};
  std::atomic<bool> bad{false}; // Catch2 macros are main-thread-only
  std::thread reader([&]() {
    while (!stop.load())
    {
      GetStaticResult r = a.getStatic("app.css");
      if (r.status != GetStaticResult::Status::Found || r.blob._entry != nullptr)
      {
        bad.store(true); // expect Found + zero-copy (_entry null)
      }
    }
  });
  for (int i = 0; i < 500; ++i)
  {
    a.reload(); // no-op, must not race the concurrent reader
  }
  stop.store(true);
  reader.join();
  REQUIRE_FALSE(bad.load());
}

TEST_CASE("getTemplate copy-before-reload contract (H-5)", "[assets][filesystem][template]")
{
  TempTree tree("tplreload");
  tree.writeTemplate("p.html", "<b>original</b>");
  Assets a = Assets::fromDirectory(tree.root);
  auto v = a.getTemplate("p.html");
  REQUIRE(v.has_value());
  std::string copy(*v); // caller copies BEFORE any reload (the documented contract)
  tree.writeTemplate("p.html", "<b>changed</b>");
  a.reload();
  REQUIRE(copy == "<b>original</b>");
  auto v2 = a.getTemplate("p.html");
  REQUIRE(v2.has_value());
  REQUIRE(*v2 == "<b>changed</b>");
}

TEST_CASE("Filesystem-mode traversal rejection (OQ-9/M-d/M-e, exercises isContained)",
          "[assets][traversal][filesystem]")
{
  TempTree tree("fstraversal");
  tree.writeStatic("ok/real.css", "ok");
  Assets a = Assets::fromDirectory(tree.root);

  // control: a legitimate nested file is served
  REQUIRE(a.getStatic("ok/real.css").status == GetStaticResult::Status::Found);

  // lexical vectors reach filesystem mode and are Rejected
  REQUIRE(a.getStatic("../etc/passwd").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("ok/../../bar").status == GetStaticResult::Status::Rejected);
  REQUIRE(a.getStatic("/abs").status == GetStaticResult::Status::Rejected);
  // a benign non-existent file is NotFound, not Rejected
  REQUIRE(a.getStatic("ok/missing.css").status == GetStaticResult::Status::NotFound);

  // M-e symlink escape + M-d sibling-prefix escape — exercised via on-disk
  // symlinks (the only way to reach isContained's weakly_canonical backstop).
  // Guarded: skip the symlink assertions if the platform/privilege disallows them.
  std::error_code ec;
  fs::create_directories(tree.root / "secret");
  std::ofstream(tree.root / "secret" / "s.txt", std::ios::binary) << "TOPSECRET";
  fs::create_directory_symlink(tree.root / "secret", tree.root / "static" / "leak", ec);
  if (!ec)
  {
    // symlink inside static/ pointing OUTSIDE static/ -> escapes root -> Rejected
    REQUIRE(a.getStatic("leak/s.txt").status == GetStaticResult::Status::Rejected);
  }
  else
  {
    WARN("symlink creation unsupported here; skipping symlink-escape assertion");
  }
  fs::create_directories(tree.root / "static-evil");
  std::ofstream(tree.root / "static-evil" / "e.txt", std::ios::binary) << "EVIL";
  fs::create_directory_symlink(tree.root / "static-evil", tree.root / "static" / "sib", ec);
  if (!ec)
  {
    // sibling dir sharing the root's name PREFIX (static vs static-evil) ->
    // component-wise containment rejects it (a string starts_with would not).
    REQUIRE(a.getStatic("sib/e.txt").status == GetStaticResult::Status::Rejected);
  }
  // web M-3: a LEGITIMATE within-root symlink asset must STILL serve — the
  // O_NOFOLLOW open is on the resolved canonical target, not the symlink itself.
  fs::create_symlink(tree.root / "static" / "ok" / "real.css",
                     tree.root / "static" / "alias.css", ec);
  if (!ec)
  {
    GetStaticResult aliased = a.getStatic("alias.css");
    REQUIRE(aliased.status == GetStaticResult::Status::Found);
    REQUIRE(aliased.blob.bytes == "ok");
  }
}

TEST_CASE("Filesystem gzip sibling variant + distinct gzipEtag", "[assets][filesystem][gzip]")
{
  TempTree tree("fsgzip");
  tree.writeStatic("a.css", "body{color:green}");
  tree.writeStatic("a.css.gz", std::string("\x1f\x8b\x08", 3) + "fake-gz");
  tree.writeStatic("b.css", "h1{}"); // no .gz sibling

  Assets a = Assets::fromDirectory(tree.root);
  GetStaticResult ra = a.getStatic("a.css");
  REQUIRE(ra.status == GetStaticResult::Status::Found);
  REQUIRE(ra.blob.gzipVariantExists);
  REQUIRE(ra.blob.gzipBytes.has_value());
  REQUIRE(ra.blob.gzipEtag.size() == 22); // 16-byte base64url, no pad
  REQUIRE(std::string(ra.blob.gzipEtag) != std::string(ra.blob.rawEtag));

  GetStaticResult rb = a.getStatic("b.css");
  REQUIRE(rb.status == GetStaticResult::Status::Found);
  REQUIRE_FALSE(rb.blob.gzipVariantExists);
  REQUIRE_FALSE(rb.blob.gzipBytes.has_value());
  REQUIRE(rb.blob.gzipEtag.empty());
}

TEST_CASE("Zero-byte asset is served with a stable etag (L-6)", "[assets][filesystem]")
{
  TempTree tree("zerobyte");
  tree.writeStatic("empty.txt", "");
  Assets a = Assets::fromDirectory(tree.root);
  GetStaticResult r = a.getStatic("empty.txt");
  REQUIRE(r.status == GetStaticResult::Status::Found);
  REQUIRE(r.blob.bytes.empty());
  REQUIRE_FALSE(r.blob.rawEtag.empty()); // SHA-256 of "" is well-defined
}

TEST_CASE("Populate-vs-reload race on initially-empty cache (thread M-4)", "[assets][concurrency]")
{
  TempTree tree("popvsreload");
  tree.writeStatic("a.txt", "racey");
  Assets a = Assets::fromDirectory(tree.root); // cache starts empty

  std::atomic<bool> stop{false};
  std::atomic<int> reads{0};
  std::atomic<bool> bad{false}; // Catch2 macros are main-thread-only
  std::thread reader([&]() {
    while (!stop.load())
    {
      GetStaticResult r = a.getStatic("a.txt"); // may be a cold miss racing reload
      if (r.status == GetStaticResult::Status::Found)
      {
        std::string b(r.blob.bytes); // full-byte read
        if (b.empty())
        {
          bad.store(true);
        }
        ++reads;
      }
    }
  });
  std::thread writer([&]() {
    for (int i = 0; i < 300; ++i)
    {
      a.reload(); // repeatedly clears the cache while the reader populates it
    }
  });
  writer.join();
  // Wait (BOUNDED — can never hang) for at least one successful read.
  for (int g = 0; reads.load() == 0 && g < 2000000; ++g)
  {
    std::this_thread::yield();
  }
  stop.store(true);
  reader.join();
  REQUIRE_FALSE(bad.load());
  REQUIRE(reads.load() > 0);
}

TEST_CASE("RD-11 embedded-external concurrent read + reload (model A, lock-free)",
          "[assets][concurrency][external]")
{
  TempTree tree("extconc");
  fs::path extDir = tree.root / "ext";
  fs::create_directories(extDir);
  std::ofstream(extDir / "img.png", std::ios::binary) << "PNGBYTES";
  std::string extDirStr = extDir.string();
  std::string_view extPaths[] = {"img.png"};

  EmbeddedAssetRegistry reg = makeRegistry();
  reg.externalDir = extDirStr;
  reg.externalPaths = extPaths;
  reg.externalPathsCount = 1;
  Assets a = Assets::fromEmbedded(reg);

  std::atomic<bool> stop{false};
  std::atomic<bool> bad{false}; // Catch2 macros are main-thread-only
  std::thread reader([&]() {
    while (!stop.load())
    {
      GetStaticResult r = a.getStatic("img.png");
      if (r.status != GetStaticResult::Status::Found ||
          std::string(r.blob.bytes) != "PNGBYTES" || // full-byte read
          r.blob._entry == nullptr)                   // owned per-request handle
      {
        bad.store(true);
      }
    }
  });
  for (int i = 0; i < 300; ++i)
  {
    a.reload(); // no-op in embedded mode, must not race the external reads
  }
  stop.store(true);
  reader.join();
  REQUIRE_FALSE(bad.load());
}

TEST_CASE("Assets is copyable and movable (M-a value-type contract)", "[assets][value]")
{
  EmbeddedAssetRegistry reg = makeRegistry();
  Assets a = Assets::fromEmbedded(reg);
  Assets copy = a;            // copy-construct
  Assets moved = std::move(a); // move-construct
  Assets assignTarget = Assets::fromEmbedded(reg);
  assignTarget = copy;        // copy-assign (would not compile if reference member)
  REQUIRE(assignTarget.getStatic("app.css").status == GetStaticResult::Status::Found);
  REQUIRE(moved.getStatic("app.js").status == GetStaticResult::Status::Found);
}
