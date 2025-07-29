add_library(testplugin SHARED TestPlugin.cpp)
target_include_directories(testplugin PRIVATE
  ${CMAKE_SOURCE_DIR}/include
  ${CPR_INCLUDE_DIR}
  ${NLOHMANN_JSON_INCLUDE_DIR}
  ${CPP_HTTPLIB_INCLUDE_DIR}
  ${TOMLPLUSPLUS_INCLUDE_DIR}
)
target_link_libraries(testplugin PRIVATE iora_lib cpr::cpr)
set_target_properties(testplugin PROPERTIES OUTPUT_NAME "testplugin")
set_target_properties(testplugin PROPERTIES PREFIX "")
