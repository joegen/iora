# Copyright (c) 2025 Joegen Baclor
# SPDX-License-Identifier: MPL-2.0
#
# Out-of-tree consumer sub-project (H-6/R-14 proof): a real find_package(Iora)
# consumer that calls iora_embed_assets() against the INSTALLED iora package.
# Driven from iora's CTest via run_embed_assets_test.cmake.

cmake_minimum_required(VERSION 3.14)
project(iora_embed_assets_consumer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Iora REQUIRED)

# H-6/R-14 proof: configure FAILS if iora_embed_assets() is not in scope after
# find_package(Iora) (also guards against a stale/partial install).
if(NOT COMMAND iora_embed_assets)
  message(FATAL_ERROR "iora_embed_assets() is not in scope after find_package(Iora) "
                      "— the H-6/R-14 distribution gap is NOT closed")
endif()

add_executable(consumer consumer.cpp)
# Iora::iora_lib carries the headers/targets; the asset ETag path is header-inline
# crypto (SecureRng::sha256 -> OpenSSL EVP), so a consumer TU that instantiates it
# must link OpenSSL::Crypto directly. find_package(Iora) already pulled OpenSSL via
# find_dependency, so the target is in scope.
target_link_libraries(consumer PRIVATE Iora::iora_lib OpenSSL::Crypto)

set(_extra_args "")
if(CONSUMER_NO_VENDOR)
  list(APPEND _extra_args NO_VENDOR_HTMX)
  target_compile_definitions(consumer PRIVATE EXPECT_HTMX=0)
else()
  target_compile_definitions(consumer PRIVATE EXPECT_HTMX=1)
endif()

iora_embed_assets(
  TARGET consumer
  TEMPLATES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/templates"
  STATIC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/static"
  HEADER_OUT "${CMAKE_CURRENT_BINARY_DIR}/gen/embedded_assets.hpp"
  REGISTRY_NAME kEmbeddedAssets
  PRECOMPRESS gzip
  ${_extra_args}
)
