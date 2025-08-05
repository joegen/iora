# CMake configuration for the sample microservice application

# Create the sample microservice executable
add_executable(microservice_example microservice_example.cpp)

# Configure with common Iora settings, OpenSSL, and tiktoken support
configure_iora_target(microservice_example 
    ENABLE_OPENSSL 
    ENABLE_TIKTOKEN
)