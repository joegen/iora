add_library(iora_core SHARED iora_core.cpp)

target_compile_features(iora_core PUBLIC cxx_std_17)

target_include_directories(iora_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(iora_core PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_definitions(iora_core PRIVATE IORA_CORE_BUILDING)

set_target_properties(iora_core PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
