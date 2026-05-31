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
