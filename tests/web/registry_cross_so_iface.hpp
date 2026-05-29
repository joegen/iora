// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// Shared interface for the ServiceRegistry cross-.so test. Included by both the
// core-process test and the test plugin, so std::type_index(typeid(IFoo))
// compares equal across the .so boundary (the abiInvariant ServiceRegistry
// relies on: default visibility + RTTI + same toolchain).

#pragma once

#include <string>

namespace iora_web_crossso_test
{

/// \brief A trivial cross-.so interface a test plugin implements and the core
/// process retrieves via ServiceRegistry::get<IFoo>().
struct IFoo
{
  virtual ~IFoo() = default;
  virtual int magic() const = 0;
  virtual std::string name() const = 0;
};

} // namespace iora_web_crossso_test
