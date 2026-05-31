// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Out-of-tree consumer of the iora_embed_assets()-generated header. Asserts the
// generated registry compiles, constructs an Assets, and serves expected
// content/MIME/ETag. Prints app.js bytes on stdout for the incremental-rebuild
// check. Exit code 0 = all assertions pass.

#include "embedded_assets.hpp"

#include <cstdio>
#include <string>
#include <string_view>

#ifndef EXPECT_HTMX
#define EXPECT_HTMX 1
#endif

static int failures = 0;

static void check(bool cond, const char *what)
{
  if (!cond)
  {
    std::fprintf(stderr, "ASSERT FAILED: %s\n", what);
    ++failures;
  }
}

int main()
{
  iora::web::Assets a = iora::web::Assets::fromEmbedded(kEmbeddedAssets);

  iora::web::GetStaticResult js = a.getStatic("app.js");
  check(js.status == iora::web::GetStaticResult::Status::Found, "app.js Found");
  check(js.blob.mime == "text/javascript", "app.js mime text/javascript");
  check(js.blob.rawEtag.size() == 32, "embedded etag is 32 hex chars");
  check(js.blob.rawEtag.front() != '"' && js.blob.rawEtag.back() != '"',
        "etag is unquoted");
  // M-7: the PRECOMPRESS gzip build-time path produces a distinct gzipEtag.
  check(js.blob.gzipVariantExists, "app.js has a gzip variant (PRECOMPRESS gzip)");
  check(js.blob.gzipEtag.size() == 32, "gzipEtag is 32 hex chars");
  check(std::string(js.blob.gzipEtag) != std::string(js.blob.rawEtag),
        "gzipEtag distinct from rawEtag (per-representation validator)");

  // M-4: image/font assets are embedded with correct MIME and are NOT gzipped
  // (already-compressed formats are skipped at build time).
  iora::web::GetStaticResult png = a.getStatic("logo.png");
  check(png.status == iora::web::GetStaticResult::Status::Found, "logo.png Found");
  check(png.blob.mime == "image/png", "logo.png mime image/png");
  check(!png.blob.gzipVariantExists, "logo.png not gzip-precompressed (skip-list)");
  iora::web::GetStaticResult font = a.getStatic("font.woff2");
  check(font.status == iora::web::GetStaticResult::Status::Found, "font.woff2 Found");
  check(font.blob.mime == "font/woff2", "font.woff2 mime font/woff2");
  check(!font.blob.gzipVariantExists, "font.woff2 not gzip-precompressed (skip-list)");

  check(a.getTemplate("index.html").has_value(), "index.html template present");
  check(a.getStatic("missing.css").status ==
          iora::web::GetStaticResult::Status::NotFound,
        "missing -> NotFound");

  iora::web::GetStaticResult htmx = a.getStatic("htmx.min.js");
#if EXPECT_HTMX
  check(htmx.status == iora::web::GetStaticResult::Status::Found,
        "vendored htmx.min.js present by default");
  check(htmx.blob.mime == "text/javascript", "htmx.min.js mime text/javascript");
#else
  check(htmx.status == iora::web::GetStaticResult::Status::NotFound,
        "htmx.min.js absent with NO_VENDOR_HTMX");
#endif

  if (failures != 0)
  {
    return 1;
  }
  // Emit app.js bytes for the incremental-rebuild content check.
  std::fwrite(js.blob.bytes.data(), 1, js.blob.bytes.size(), stdout);
  return 0;
}
