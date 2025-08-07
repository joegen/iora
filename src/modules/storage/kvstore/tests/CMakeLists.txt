create_iora_test_target(iora_test_mod_kvstore
    SOURCES iora_test_mod_kvstore.cpp
)

target_include_directories(iora_test_mod_kvstore PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Register the test with CTest
add_test(NAME IoraTestKvStore COMMAND iora_test_mod_kvstore)