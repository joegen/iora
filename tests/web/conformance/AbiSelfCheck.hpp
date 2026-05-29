// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// OPTIONAL cross-.so ABI self-check for the ServiceRegistry abiInvariant (R-12).
// Belt-and-suspenders runtime guard that fails loudly if a consumer has drifted
// to -fvisibility=hidden or -fno-rtti — which would make std::type_index stop
// comparing equal across the .so boundary and silently make
// ServiceRegistry::get<T>() return nullptr.
//
// Like the other conformance fixtures, this lives in iora's tree but runs in the
// consuming plugin's CI (iora_web_middleware), NOT in iora's gate. It is most
// useful when the type name is captured in the REGISTERING translation unit (the
// plugin) and passed here (the consuming TU): if the two names differ, RTTI/
// visibility has drifted.

#pragma once

#include <catch2/catch.hpp>

#include "iora/core/service_registry.hpp"

#include <memory>
#include <string>
#include <typeinfo>

namespace iora
{
namespace web
{
namespace conformance
{

/// \brief Assert the RTTI type name of Iface observed in THIS translation unit
/// is non-empty and matches the name observed in the registering TU. A mismatch
/// means RTTI/visibility drift (the abiInvariant is broken).
/// \param nameInRegisteringTu typeid(Iface).name() captured by the plugin that
///        registered the implementation.
template <typename Iface> inline void runAbiTypeNameSelfCheck(const std::string &nameInRegisteringTu)
{
  const std::string here = typeid(Iface).name();
  REQUIRE_FALSE(here.empty());
  REQUIRE(here == nameInRegisteringTu);
}

/// \brief End-to-end ABI self-check: register an Iface implementation under a
/// module id and confirm get<Iface>() observes it. If type_index has drifted
/// across the consuming TUs, get<Iface>() returns nullptr and this fails loudly.
/// Cleans up the registration afterwards.
template <typename Iface, typename Impl>
inline void runAbiRoundTripSelfCheck(const std::string &moduleId)
{
  auto impl = std::make_shared<Impl>();
  iora::ServiceRegistry::set<Iface>(impl, moduleId);
  auto got = iora::ServiceRegistry::get<Iface>();
  REQUIRE(got != nullptr);
  REQUIRE(got.get() == impl.get());
  iora::ServiceRegistry::unregisterModule(moduleId);
  REQUIRE(iora::ServiceRegistry::get<Iface>() == nullptr);
}

} // namespace conformance
} // namespace web
} // namespace iora
