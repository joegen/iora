# CMake configuration for Iora tests

# Create the main test executable with all tests
create_iora_test_target(all_tests
    SOURCES all_tests.cpp
)

# Register the test with CTest
add_test(NAME AllTests COMMAND all_tests)

# Build test plugins for dynamic loading tests
add_subdirectory(plugins)