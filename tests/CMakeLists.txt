# CMake configuration for Iora tests

# Create the main test executable with all tests
create_iora_test_target(iora_test
    SOURCES iora_test_main.cpp
)

# Register the test with CTest
add_test(NAME IoaraTest COMMAND iora_test)

# Build test plugins for dynamic loading tests
add_subdirectory(plugins)