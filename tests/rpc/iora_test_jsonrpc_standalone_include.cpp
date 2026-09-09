// Copyright (c) 2025 Joegen Baclor
// SPDX-License-Identifier: MPL-2.0
//
// task-1.4: carrier-agnostic invariant probe. This translation unit includes
// ONLY iora/rpc/jsonrpc_server.hpp and nothing else, proving the protocol header
// compiles standalone — no network header, no iora/iora.hpp, no include-order
// dependency. Registered as a COMPILE-ONLY object-library target by task-2.1; it
// has no main() and is never run.
#include "iora/rpc/jsonrpc_server.hpp"
