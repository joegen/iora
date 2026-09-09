# Flagship example programs for the iora documentation set (DQ8=C).
#
# Each example is a standalone executable configured via
# configure_iora_target(<tgt> ENABLE_OPENSSL) -- NOT bare iora_lib: iora_lib is an
# INTERFACE target that links iora_core, which links OpenSSL PRIVATE, so an
# executable whose TU includes rpc/network/web headers (transitively <openssl/...>)
# needs the OpenSSL link + include dirs. configure_iora_target adds those
# unconditionally (target_link_libraries iora_lib + OpenSSL::SSL/Crypto), and the
# ENABLE_OPENSSL keyword additionally sets the cpp-httplib TLS define. This is the
# same path create_iora_test_target uses.

add_executable(jsonrpc_example jsonrpc_example.cpp)
configure_iora_target(jsonrpc_example ENABLE_OPENSSL)
