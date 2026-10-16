add_library(iora_core SHARED iora_core.cpp)

target_compile_features(iora_core PUBLIC cxx_std_17)

target_include_directories(iora_core PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(iora_core PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# The headers call dlopen/dlclose/dlsym inline (plugin_loader.hpp), so consumers
# need the dl library too on glibc < 2.34.
target_link_libraries(iora_core PUBLIC ${CMAKE_DL_LIBS})

target_compile_definitions(iora_core PRIVATE IORA_CORE_BUILDING)

# Anyone linking iora_core must use its out-of-line singletons; without this a
# consumer linking iora_core directly (not via iora_lib) compiles per-image copies.
target_compile_definitions(iora_core INTERFACE IORA_CORE_SHARED)

set_target_properties(iora_core PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)
