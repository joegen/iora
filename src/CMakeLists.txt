add_executable(iora iora.cpp)

# Configure with common Iora settings, OpenSSL, and tiktoken support
configure_iora_target(iora 
    ENABLE_OPENSSL 
    ENABLE_TIKTOKEN
)

# Default config path = where install puts iora.cfg (CMakeLists.txt rule).
target_compile_definitions(iora PRIVATE IORA_INSTALLED_CONFIG_FILE="${_iora_installed_config_file}")

# Install the main iora application binary
install(TARGETS iora
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)