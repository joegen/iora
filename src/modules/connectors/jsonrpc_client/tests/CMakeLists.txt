# JSON-RPC Client Module Tests
add_compile_options(-Wno-free-nonheap-object)

# Create real client-server integration test with actual IoraService
create_iora_test_target(iora_test_mod_jsonrpc_client_server_real
    SOURCES iora_test_mod_jsonrpc_client_server_real.cpp
)

# Ensure both server and client plugins are built before this test
add_dependencies(iora_test_mod_jsonrpc_client_server_real 
    mod_jsonrpc_server 
    mod_jsonrpc_client
)

add_test(NAME JsonRpcClientServerRealTest COMMAND iora_test_mod_jsonrpc_client_server_real)

# ---------------------------------------------------------------------------
# JSON-RPC negotiated-gzip Consumer C — foundation slice: PORTED (tracker
# 2026-07-26-1 task-6.7) to tests/rpc/iora_test_jsonrpc_gzip_foundation.cpp under
# namespace iora::rpc (its one plugin/getConfig-seam case rewritten to a direct
# JsonRpcHttpOptions defaults check). Old source + registration removed here as
# the other half of the move.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# JSON-RPC negotiated-gzip Consumer C — request direction: PORTED (tracker
# 2026-07-26-1 task-6.7) to tests/rpc/iora_test_jsonrpc_gzip_request.cpp under
# namespace iora::rpc (server side rewritten to compose HttpServer + JsonRpcServer
# + JsonRpcHttpEndpoint; the _requestCompressionMutex TSan probe preserved). Old
# source + registration removed here as the other half of the move.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# JSON-RPC negotiated-gzip Consumer C — response direction: PORTED (tracker
# 2026-07-26-1 task-6.7) to tests/rpc/iora_test_jsonrpc_gzip_response.cpp under
# namespace iora::rpc (server side composes HttpServer + JsonRpcServer +
# JsonRpcHttpEndpoint). Old source + registration removed here as the move.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Pool lifetime / identity concurrency suite: PORTED (tracker 2026-07-26-1
# task-6.5) to tests/rpc/iora_test_jsonrpc_client_pool.cpp under namespace
# iora::rpc (JsonRpcClientTestAccess seam moved with it; default tag-filtered
# registration + the four CR per-repro guards re-registered there). Old source +
# registration removed here as the other half of the move.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# task-3.2 — self-destruct detection. PORTED (tracker 2026-07-26-1 task-6.6) to
# tests/rpc/iora_test_jsonrpc_quiesce_selfdestruct.cpp under namespace iora::rpc.
# The old source + registration are removed here as the other half of the move so
# the ported target (same basename) does not collide during the port->phase-9
# deletion window. The remaining src/modules tree is deleted by task-9.1.
# ---------------------------------------------------------------------------
