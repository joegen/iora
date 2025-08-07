add_executable(iora iora.cpp)

# Configure with common Iora settings, OpenSSL, and tiktoken support
configure_iora_target(iora 
    ENABLE_OPENSSL 
    ENABLE_TIKTOKEN
)

add_subdirectory(modules/storage/kvstore)